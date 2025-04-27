# Issuing Test Credentials

* Add your credentials in `database_in.json`

* Run `create_database.py`

    ```
    $ cd <project-root>/app
    $ python3 -m venv env
    $ . env/bin/activate
    $ pip install -r requirements.txt
    $ python testdata/create_database.py
    ```

* See output at `database.json`