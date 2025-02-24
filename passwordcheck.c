/*-------------------------------------------------------------------------
 *
 * passwordcheck.c
 *
 * PostgreSQL password check extension with expiration date validation.
 * Ensures passwords meet complexity requirements and that expiration dates
 * are specified and not more than 90 days in the future. Also ensures that
 * expiration dates are checked during ALTER ROLE commands.
 *
 * IDENTIFICATION
 *     contrib/passwordcheck/passwordcheck.c
 *-------------------------------------------------------------------------*/

#include "postgres.h"
#include <ctype.h>
#include <time.h>

#ifdef USE_CRACKLIB
#include <crack.h>
#endif

#include "commands/user.h"
#include "commands/alter.h"
#include "fmgr.h"
#include "libpq/crypt.h"
#include "utils/timestamp.h"
#include "utils/datetime.h"
#include "utils/date.h"
#include "tcop/utility.h"  /* For ProcessUtility_hook */

PG_MODULE_MAGIC;

/* Saved hook value in case of unload */
static check_password_hook_type prev_check_password_hook = NULL;
static ProcessUtility_hook_type prev_utility_hook = NULL;

/* Password policy constants */
#define MIN_PWD_LENGTH 8
#define MAX_PWD_VALIDITY_DAYS 90

/*
 * calculate_max_valid_until
 * Computes the maximum allowed password expiration timestamp (now + 90 days).
 */
static TimestampTz calculate_max_valid_until(TimestampTz now)
{
    time_t now_time = timestamptz_to_time_t(now);
    now_time += MAX_PWD_VALIDITY_DAYS * 24 * 60 * 60; /* 90 days */
    return time_t_to_timestamptz(now_time);
}

/*
 * validate_password_expiration
 * Checks if the provided expiration date is within the allowed limit.
 */
static void validate_password_expiration(Datum validuntil_time, bool validuntil_null)
{
    if (validuntil_null)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password expiration date must be specified")));
    }

    TimestampTz expiration = DatumGetTimestampTz(validuntil_time);
    TimestampTz now = GetCurrentTimestamp();
    TimestampTz max_valid_until = calculate_max_valid_until(now);

    if (timestamp_cmp_internal(expiration, max_valid_until) > 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password expiration date must not be more than %d days in the future", MAX_PWD_VALIDITY_DAYS)));
    }
}

/*
 * check_password
 * Verifies password complexity and expiration date constraints.
 */
static void check_password(const char *username,
                           const char *shadow_pass,
                           PasswordType password_type,
                           Datum validuntil_time,
                           bool validuntil_null)
{
    if (prev_check_password_hook)
        prev_check_password_hook(username, shadow_pass, password_type, validuntil_time, validuntil_null);

    validate_password_expiration(validuntil_time, validuntil_null);

    if (password_type != PASSWORD_TYPE_PLAINTEXT)
    {
        const char *logdetail = NULL;

        if (plain_crypt_verify(username, shadow_pass, username, &logdetail) == STATUS_OK)
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password must not equal user name")));
    }
    else
    {
        const char *password = shadow_pass;
        int pwdlen = strlen(password);
        bool pwd_has_letter = false, pwd_has_upper = false, pwd_has_number = false, pwd_has_non_alnum = false;

#ifdef USE_CRACKLIB
        const char *reason;
#endif

        if (pwdlen < MIN_PWD_LENGTH)
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password is too short (minimum length is %d characters)", MIN_PWD_LENGTH)));

        if (strstr(password, username))
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password must not contain user name")));

        for (int i = 0; i < pwdlen; i++)
        {
            unsigned char ch = (unsigned char) password[i];

            if (isalpha(ch))
            {
                pwd_has_letter = true;
                if (isupper(ch))
                    pwd_has_upper = true;
            }
            else if (isdigit(ch))
            {
                pwd_has_number = true;
            }
            else
            {
                pwd_has_non_alnum = true;
            }
        }

        if (!pwd_has_letter || !pwd_has_upper || !pwd_has_number || !pwd_has_non_alnum)
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password must contain letters, at least one uppercase letter, numbers, and non-alphanumeric characters")));

#ifdef USE_CRACKLIB
        if ((reason = FascistCheck(password, CRACKLIB_DICTPATH)))
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password is easily cracked"),
                     errdetail_log("cracklib diagnostic: %s", reason)));
#endif
    }
}

/*
 * passwordcheck_utility_hook
 * Intercepts utility commands to enforce password expiration on ALTER ROLE.
 */
static void passwordcheck_utility_hook(PlannedStmt *pstmt,
                                       const char *queryString,
                                       bool readOnlyTree,
                                       ProcessUtilityContext context,
                                       ParamListInfo params,
                                       QueryEnvironment *queryEnv,
                                       DestReceiver *dest,
                                       QueryCompletion *qc)
{
    if (IsA(pstmt->utilityStmt, AlterRoleStmt))
    {
        AlterRoleStmt *stmt = (AlterRoleStmt *) pstmt->utilityStmt;
        ListCell *option;
        bool validuntil_found = false;

        foreach(option, stmt->options)
        {
            DefElem *defel = (DefElem *) lfirst(option);
            if (strcmp(defel->defname, "validUntil") == 0)
            {
                validuntil_found = true;
                break;
            }
        }

        if (!validuntil_found)
        {
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("ALTER ROLE must specify a password expiration date using VALID UNTIL")));
        }
    }

    if (prev_utility_hook)
        prev_utility_hook(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}

/*
 * _PG_init
 * Module load callback.
 */
void _PG_init(void)
{
    elog(LOG, "passwordcheck extension loaded successfully");
    prev_check_password_hook = check_password_hook;
    check_password_hook = check_password;

    prev_utility_hook = ProcessUtility_hook;
    ProcessUtility_hook = passwordcheck_utility_hook;
}

/*
 * _PG_fini
 * Module unload callback.
 */
void _PG_fini(void)
{
    ProcessUtility_hook = prev_utility_hook;
    check_password_hook = prev_check_password_hook;
}
