FROM python:3.10.1-slim-buster
RUN apt-get update && apt-get -y install cron vim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt
COPY crontab /etc/cron.d/crontab
COPY aliyun_ddns.py /app/aliyun_ddns.py
RUN chmod 0644 /etc/cron.d/crontab
RUN /usr/bin/crontab /etc/cron.d/crontab
CMD ["cron", "-f"]
