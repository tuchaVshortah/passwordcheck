# Updates are coming soon
_Inspired and written by ChatGPT_ <br/>
_Tested and validated by Me_

# passwordcheck
PostgreSQL passwordcheck implementation

# Functionality
Captures CREATE ROLE and ALTER ROLE requests. Currently validates if a passwords has at least 8 symbols including at least 1 uppercase letter, 1 non alphabetic and non numeric symbol, at least 1 number and letters

# Build
- Download the Postgresql source
- Untar
- Navigate to contrib/passwordcheck
- Modify passwordcheck.c contents (paste this file)
- Go to the root of the source tree
- Run ./configure and fix errors if any
- Run make
- Navigate to contrib/passwordcheck
- Run make
- Run sudo systemctl stop postgresql.service
- Run sudo make install
- Update /etc/postgresql/16/main/postgresql.conf: modify shared_preload_libraries and include /usr/local/pgsql/lib/passwordcheck
- Run sudo systemctl start postgresql.service

# Contribute
Any suggestions are welcomed. Feel free to create issues.
