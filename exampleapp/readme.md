Example App
===========

admin password is ``admin:password``


This is just a simple example app, used for testing and showing how things work
```
mkdir -p exampleapp/static exampleapp/media/static

PYTHONPATH=$PYTHONPATH:$PWD django-admin.py collectstatic --noinput --settings=exampleapp.settings

PYTHONPATH=$PYTHONPATH:$PWD django-admin.py runserver --settings=exampleapp.settings
```
