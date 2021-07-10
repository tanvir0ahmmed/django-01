release: python manage.py makemigrations --no-input
release: python manage.py migrate --no-input
python manage.py collectstatic --no-input

web: gunicorn blog.wsgi