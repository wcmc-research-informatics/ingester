# HealthPro Data Ingester

This software parses data from a HealthPro Work Queue CSV and imports it into a database, and also performs ancillary tasks.

It was developed to facilitate _All of Us_ Research Program efforts at Weill Cornell Medicine. (HealthPro is software for use by _All of Us_ personnel.) _All of Us_ is a national program designed to gather data from one million or more people living in the United States to accelerate research and improve health. More information here: https://allofus.nih.gov.

## How It Works

The ingester runs as a server process that monitors an inbox folder for the appearance of new files; it goes to work when a new HealthPro Work Queue CSV appears (deposited by a researcher or other study personnel).

The name and contents of the CSV file should not be modified in any way prior to putting it into the inbox folder.

Once the file appears, these are the steps it takes (at a high level):

* The ingester does some light validation on the file, sending a notification email if the file doesn't appear to be a valid Work Queue CSV (or if it's not a CSV at all).
* If the file appears valid, it then parses the CSV file and imports it into a destination database table (truncating it first).
* It saves the CSV in an archive folder and deletes it from the inbox folder.
* It subsequently runs a SQL Server Agent job which reads data from a REDCap project, pivots and transforms the data, and inserts it into the destination database.
* A metadata table is also updated noting the time that both the HealthPro and REDCap data were last refreshed. For the HealthPro data, it uses the date/time info from the CSV filename.
* It sends an email to the team letting them know if the process succeeded or failed.

### CSV Validation and Safeguards

There are a number of safeguards in place including:

* Ensuring the columns in the CSV match that of the target database table (this likely means a new version of HealthPro has been deployed and the ingester needs to be updated).
* Ensuring that the number of rows in the CSV are the same or greater than in the database (to prevent accidentally processing an old file).

## Requirements
* Targets Python 2.7 on Linux
* pip
* virtualenv
* SQL Server
* Package requirements are listed in `requirements.txt` (use `installdeps.sh`; see below for step-by-step details)

## Configuration / First-Time Setup

### Database

The ingester currently works with SQL Server. 

**Create the database tables** in SQL Server using the following files:

* `sql/create-healthpro-table.sql`
* `sql/create-metadata-table.sql`
* `sql/create-redcap-table.sql`

Customize the database, schema, and table names to suit.

### Application Folders

Create runtime and staging folders.

~~~
mkdir ingester-staging
mkdir ingester
~~~

In the `ingester` folder, create the following subfolders:

~~~
cd ingester
mkdir archive
mkdir enclave
~~~

The archive folder holds processed CSVs.

The enclave folder will hold the configuration file (see below).

### Inbox Folder

The inbox folder (where a CSV can be deposited by a researcher) can be anything you want. You'll then put its location in the config file (see below).

### Configuration File (enclave folder)

In the `enclave` folder, create a file named ````healthproimporter_config.json````. It should contain JSON like so

    { "inbox_dir": "/path/to/inbox"
    , "archive_dir": "/path/to/archive"
    , "consortium_tag": "CONSORTIUM"
    , "db_info" : { "host": "X"
                  , "user": "X" 
                  , "password": "X" }
    , "healthpro_table_name": "[dm_aou].[dbo].[healthpro]"
    , "metadata_table_name": "[dm_aou].[dbo].[metadata]"
    , "redcap_table_name": "[dm_aou].[dbo].[redcap]"
    , "run-redcap-refresh" : "yes"
    , "redcap_job_name": "DM_AOU REDCap Refresh Decoupled"
    , "agent_job_timeout": 900
    , "from_email": "X"
    , "to_email": "X"
    , "admin_email": "X"
    , "paired_organization": "MY_PAIRED_ORGANIZATION"
    , "start-telemetry-ping-listener": "yes"
    , "path-to-private-key": "/path/to/private.key"
    , "path-to-public-pem": "/path/to/public.pem"
    , "telemetry-ping-port": 31000
    , "telemetry-ping-route": "ping-ingester"
    }

Customize the configuration values to suit. The email addresses are for success, error, and notification emails to be sent to the team.

#### run-redcap-refresh flag

Set this to 'no' if you want to skip the step that refreshes REDCap (via SQL Server Agent job).

#### start-telemetry-ping-listener flag

Optionally, Ingester can also spin up a simple Web server endpoint to assist telemetry/monitoring tools with ensuring the Ingester service is up.

Customize the URL with the telemetry-ping-route setting. The above example configuration would create a simple Web page (consisting of just the text 'pong') at the following URL:

    https://domain:31000/ping-ingester

To disable this feature, set the flag to 'no'. If turned off, the following flags are not needed:

* path-to-private-key
* path-to-public-pem
* telemetry-ping-port
* telemetry-ping-route


#### paired organization 

If the CSV file does not contain at least one row with a Paired Organization equal to the value set in the configuration file, the CSV will not be processed (an email notice will be sent).

### virtualenv

Create a virtualenv for the process to run in; from the `ingester` folder, run:

    mkdir venv
    virtualenv venv

### Deploying code and dependencies

From the `ingester-staging` folder, run:

~~~
git clone https://github.com/wcmc-research-informatics/ingester .
cp main.py requirements.txt installdeps.sh ../ingester
~~~

Then run the install script from the `ingester` folder (activate the virtualenv first):

~~~
cd ../ingester
source venv/bin/activate
./installdeps.sh
~~~


### Starting the process

Ensure you're inside the virtualenv, then start:

~~~
source venv/bin/activate
nohup python /home/ingester/main.py >> out.log 2>&1 &
~~~

You can also configure the process as a daemon; the exact method varies depending on the Linux distro you're using.

## Updating your installation
To pull in the latest version, use the steps detailed in **Deploying code anad dependencies** above, but replace the `git clone ...` command with simply this (again, run this from the `ingester-staging` folder:

~~~
git pull
~~~

## Logging

Logs are written to `log/default.log`. The logging process is self-cleaning over time.

## Notes

* Use Watchdog's PollingObserver (rather than the vanilla Observer) to observe files being delivered on a Samba share, NFS or similar.

* Transact-SQL commands for running and monitoring SQL Server Agent jobs
  * `sp_start_job` -- https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-start-job-transact-sql
  * `sp_help_job` -- ttps://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-help-job-transact-sql 

* Watchdog
  * https://pypi.python.org/pypi/watchdog
  * https://pythonhosted.org/watchdog/api.html#module-watchdog.events
  * https://pythonhosted.org/watchdog/api.html#module-watchdog.observers
  * https://stackoverflow.com/questions/24597025/using-python-watchdog-to-monitor-a-folder-but-when-i-rename-a-file-i-havent-b
  * https://pythonhosted.org/watchdog/api.html#watchdog.observers.polling.PollingObserver

* Unicode in Python 2
  * https://pythonhosted.org/kitchen/unicode-frustrations.html
  * http://farmdev.com/talks/unicode/

