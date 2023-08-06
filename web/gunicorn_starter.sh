#!/bin/sh

if [ "$APP_ENV" = "development" ]; then
    echo -n "Waiting for the DBMS to accept cennection "
    while [ 1 ]; do
        if nc -vz db "$DATABASE_PORT"; then
            break
        fi
        echo -n "."
        sleep 1
    done
    echo ""
    echo "Creating the database tables..."
    python3 manage.py create_db
    python3 manage.py seed_db
    echo "Tables created"
    if [ "$FLASK_DEBUG" = "1" ]; then
        echo "Running on Flask Development Server"
        python3 main.py
    else
        echo "Running on Gunicorn"
        gunicorn main:app -c "$PWD"/gunicorn.config.py    
    fi
else
    echo "Running on Gunicorn"
    gunicorn main:app -c "$PWD"/gunicorn.config.py
fi

exec "$@"