# Issuing Test Credentials

* Add your credentials in `database_in.json`
  * When adding a new credential, specify the claim values in `namespaces` and `paths` of an mdoc or sd-jwt credential, respectively.

* Run `create_database.py`

    ```
    $ cd <project-root>/app
    $ python3 -m venv env
    $ . env/bin/activate
    $ pip install -r requirements.txt
    $ python testdata/create_database.py
    ```

* See output at `database.json`

* Now you can copy the output over to `app/src/main/assets/databasenew.json`