#!/usr/bin/env python
# coding=utf-8
from aliyunsdkalidns.request.v20150109.DescribeSubDomainRecordsRequest import DescribeSubDomainRecordsRequest
from aliyunsdkalidns.request.v20150109.DescribeDomainRecordsRequest import DescribeDomainRecordsRequest
from aliyunsdkalidns.request.v20150109.UpdateDomainRecordRequest import UpdateDomainRecordRequest
from aliyunsdkalidns.request.v20150109.AddDomainRecordRequest import AddDomainRecordRequest
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.client import AcsClient
import ipaddress
import requests
import json
import logging
import argparse

global client

logging.basicConfig(
    level='INFO',
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


MY_DOMAIN = 'rwecho.top'
MY_Record_RR = "myhome"


def is_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def add_domain_record(rr: str, ip: str):
    if not is_ip_address(ip):
        raise ValueError(f"IP {ip} is required.")

    request = AddDomainRecordRequest()
    request.set_accept_format('json')
    request.set_Value(ip)
    request.set_Type("A")
    request.set_RR(rr)
    request.set_DomainName(MY_DOMAIN)
    response = client.do_action_with_exception(request)
    print(str(response, encoding='utf-8'))


def update_domain_record(rr: str, ip: str):
    if not is_ip_address(ip):
        raise ValueError(f"IP {ip} is required.")
    request = UpdateDomainRecordRequest()
    request.set_RR(rr)
    request.set_Value(ip)
    response = client.do_action_with_exception(request)


def get_ip_by_rr(rr: str):
    item = next((x for x in get_domain_records() if x["rr"] == rr), "")
    if item:
        return item["ip"]
    return None


def get_domain_records():
    request = DescribeDomainRecordsRequest()
    request.set_accept_format('json')
    request.set_DomainName(MY_DOMAIN)
    request.set_PageSize(100)
    response = client.do_action_with_exception(request)
    response_data = json.loads(response.decode("utf-8"))
    records = response_data['DomainRecords']['Record']

    result = []
    for record in records:
        rr = record['RR']
        ip = record['Value']
        result.append({
            "rr": rr,
            "ip": ip
        })
    return result


def get_public_ip():
    r = requests.get("http://icanhazip.com/")
    if r.ok:
        return r.text.strip()
    raise Exception("Can not get public ip")


def environ_or_required(key):
    return (
        {'default': os.environ.get(key)} if os.environ.get(key)
        else {'required': True}
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--client_id',
                        help='client id of aliyun sdks',
                        **environ_or_required('CLIENT_ID'))
    parser.add_argument('-s', '--client_secret',
                        help='client secret of aliyun skds',
                        **environ_or_required('CLIENT_SECRET'))
    args = parser.parse_args()
    try:
        global client
        client = AcsClient(args.client_id,
                           args.client_secret, 'cn-hangzhou')
        ip = get_public_ip()
        logger.info(f"my public ip: {ip}")
        rr_ip = get_ip_by_rr(MY_Record_RR)
        logger.info(f"rr {MY_Record_RR} value is {rr_ip}")
        if not rr_ip:
            add_domain_record(MY_Record_RR, ip)
            logger.info(f"add new record for {MY_Record_RR} {ip}")
        elif rr_ip != ip:
            update_domain_record(MY_Record_RR, ip)
            logger.info(f"update rr {MY_Record_RR} with ip {ip}")
        else:
            logger.debug(f"ip {ip} stay the same.")
    except Exception as exception:
        logger.error(exception)
