# Update VALID UNTIL after change password


# Creating a function
```sql
CREATE OR REPLACE FUNCTION change_own_password(newpassword TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    expiration TIMESTAMP;
BEGIN
    expiration := NOW() + INTERVAL '90 days';

    EXECUTE format('ALTER ROLE %I PASSWORD %L', SESSION_USER, newpassword);
    
    EXECUTE format('ALTER ROLE %I VALID UNTIL %L', SESSION_USER, expiration::TEXT);
END $$;
```

## Setting permissions:
```sql
GRANT EXECUTE ON FUNCTION change_own_password(TEXT) TO public;
```

## I'm testing password change and updates VALID UNTIL:

```sql
SELECT change_own_password('teestttttT0@');
```



