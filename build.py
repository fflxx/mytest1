#!/bin/env python3

import argparse
import os
import requests
import subprocess
import boto3
from botocore.exceptions import ClientError as boto3clienterror
import traceback
import json

parser = argparse.ArgumentParser()
# build command
parser.add_argument("command", help="build command")

# workdir
parser.add_argument("--workdir", help="script work dir")

parser.add_argument("--environment", default="prod", help="default:prod. prod|stage|test.")
# service name in cmdb 
parser.add_argument("-s", "--service", help="service name")

parser.add_argument("--no-envfile", action="store_true", help="not download envfile from cmdb s3 address")


args = parser.parse_args()

# -----------------------------------
environment = args.environment
arg_cmdb_secretmanager = args.cmdb_secretmanager

arg_command = args.command
arg_service = args.service
arg_no_envfile = args.no_envfile
arg_envfile_from = args.envfilefrom

print('Environment:{}|Service:{}'.format(environment, arg_service))

if (arg_service is not None) and arg_service.strip():
    arg_total_switch = True
else:
    arg_total_switch = False


if args.workdir:
    print('To change workdir to {}'.format(args.workdir))
    try:
        os.chdir(args.workdir)
    except Exception:
        print('Change workdir to {} is failed'.format(args.workdir))
        traceback.print_exc()
        exit(1)
    else:
        print('Change workdir to {} is successful'.format(args.workdir))


def get_cmdb_secretmanager():
    client = boto3.client('secretsmanager', region_name='us-west-1')
    response = client.get_secret_value(SecretId=arg_cmdb_secretmanager)
    secretmanager_data = json.loads(response['SecretString'])
    return secretmanager_data['url'], secretmanager_data['username'], secretmanager_data['password']

def get_cmdb(request_api, data_type='json'):
    cmdb_url, cmdb_username, cmdb_password = get_cmdb_secretmanager()
    if request_api.startswith('http'):
        request_url = request_api
    else:
        request_url = os.path.join(cmdb_url, request_api)
    print('cmdb request_url:{}'.format(request_url))
    request_data = requests.get(request_url, auth=(cmdb_username, cmdb_password))
    if request_data.ok:
        if data_type == 'json':
            service_data = request_data.json()
        else:
            service_data = request_data.text
        return service_data
    else:
        print('url:{}|code:{}|request cmdb error'.format(request_url, request_data.status_code))
        return False

def build(command):
    code = os.system(command)
    if code != 0:
        return False
    else:
        return True

def download_env_s3(bucket, envs3path, env_destination):
    print('download s3://{}/{} to {}'.format(bucket, envs3path, env_destination))
    if bucket and envs3path and env_destination:
        s3 = boto3.client('s3')
        try:
            s3.download_file(bucket, envs3path, env_destination)
        except boto3clienterror as error:
            print(error)
            response = error.response
            if response['ResponseMetadata']['HTTPStatusCode'] == 404:
                print('download s3://{}/{} to {} code 404'.format(bucket, envs3path, env_destination))
                return 404
            else:
                print(error)
                traceback.print_exc()
        else:
            print('download s3://{}/{} to {} successful'.format(bucket, envs3path, env_destination))
            return True
    print('download s3://{}/{} to {} failed'.format(bucket, envs3path, env_destination))
    return False

def get_s3path_bucket_object(s3path):
    _, s3_bucket_object = s3path.split('//')
    bucket, object_path = s3_bucket_object.split('/', maxsplit=1)
    return bucket, object_path

def login_codeartifact(repo, tool):
    print('CodeArtifact|repo:{}|tool:{}'.format(repo, tool))
    if repo and repo.strip():
        if tool in ('npm', 'pip'):
            command = 'aws codeartifact login --tool {} --repository {} --domain hiretual --domain-owner 780323805217 --region us-east-1'.format(tool, repo)
            print('{}|login codeartifact'.format(command))
            state = os.system(command)
            if state == 0:
                print('{}|codeartifact login successful'.format(command))
                return True
            else:
                print('{}|codeartifact login failed'.format(command))
        elif tool == 'gradle':
            command = 'aws codeartifact get-authorization-token --domain hiretual --domain-owner 780323805217 --query authorizationToken --output text --region us-east-1'
            token = subprocess.check_output(command, shell=True)
# ---------------------------
            code_conf = '''
maven {
  url 'https://hiretual-780323805217.d.codeartifact.us-east-1.amazonaws.com/maven/{}/'
  credentials {
      username "aws"
      password "{}"
  }
}
'''.format(repo, token)
# ---------------------------
            with open('build.gradle', 'a') as fd:
                fd.write(code_conf)
            print('write codeartifact token in build.gradle successful')
        else:
            print('script not support {} setting'.format(tool))
    else:
        print('Error:no codeartifact repos')
    return False

def confirm_env_files(service, environment, s3_envfiles):
    pass

def get_env_bucket(environment):
    if environment == 'prod':
        bucket = 'htm-env'
    elif environment == 'test':
        bucket = 'htm-env-test'
    elif environment == 'stage':
        bucket = 'htm-env-stage'
    elif environment == 'preprod':
        bucket = 'htm-env-preprod'
    else:
        print('Error:environment:{}|not in (prod|stage|test)').format(environment)
        return False
    return bucket

def download_env_cmdb2(service, environment):
    print('download env from cmdb|service:{}'.format(service))
    request_api = '{}/{}/{}'.format('api2env', environment, service)
    env_files_info = get_cmdb(request_api)
    if not env_files_info:
        return False
    if env_files_info['service'] != service:
        print('Error: request_api:{}|request service:{}|response service:{}|the response service != request service'.format(request_api, service, env_files_info['service']))
        return False
    env_files_list = env_files_info['files']
    if not env_files_list:
        print("Info: env list is empty in cmdb api2env, don't download env")

    for item in env_files_list:
        if item['env'] != environment and item['env'] != 'common':
            print('Error: request env:{}|response data:{}|the response env != request service and != common'.format(environment, item))
            return False
        local_path = item['local_path']
        if item['type'] == 's3':
            s3_bucket = get_env_bucket(environment)
            status = download_env_s3(s3_bucket, item['s3_path'], local_path)
            if status is True:
                continue
        elif item['type'] == 'content':
            print(item['file_url'])
            env_content = get_cmdb(item['file_url'], data_type='text')
            if env_content.strip():
                with open(local_path, 'w') as fd:
                    fd.write(env_content)
                print('download cmdb {} env to {} successful'.format(service, local_path))
                continue
            else:
                print('env_content is empty|file_url:{}'.format(item['file_url']))
        else:
            print('env file type not match|type:{}'.format(item['type']))
        return False
    else:
        return True

def download_env_cmdb(service, environment, destination):
    print('download env from cmdb|service:{}|destination:{}'.format(service, destination))
    request_api = '{}/{}/{}'.format('api2env', environment, service)
    env_files_info = get_cmdb(request_api)
    if not env_files_info:
        return False
    if env_files_info['service'] != service:
        print('Error: request_api:{}|request service:{}|response service:{}|the response service != request service'.format(request_api, service, env_files_info['service']))
        return False
    env_files_list = env_files_info['files']
    if destination.startswith('./'):
        destination = destination[2:]
    
    for item in env_files_list:
        if item['env'] != environment and item['env'] != 'common':
            print('Error: request env:{}|response data:{}|the response env != request service and != common'.format(environment, item))
            return False
        if item['local_path'] == destination:
            print('loacl_path matching|local_path:{}|destination:{}'.format(item['local_path'], destination))
            if item['type'] == 's3':
                s3_bucket = get_env_bucket(environment)
                status = download_env_s3(s3_bucket, item['s3_path'], destination)
                if status is True:
                    return True
            elif item['type'] == 'content':
                print(item['file_url'])
                env_content = get_cmdb(item['file_url'], data_type='text')
                if env_content.strip():
                    with open(destination, 'w') as fd:
                        fd.write(env_content)
                    print('download cmdb {} env to {} successful'.format(service, destination))
                    return True
                else:
                    print('env_content is empty|file_url:{}'.format(item['file_url']))
            else:
                print('env file type not match|type:{}'.format(item['type']))
            return False
    print('service:{}|request_api:{}|not match any local_path:{}'.format(service, request_api, destination))
    return False

def download_env(service_data_envs):
    #env_files = confirm_env_files(arg_service, environment, s3_envfiles)
    env_files = service_data_envs
    bucket = get_env_bucket(environment)
    if bucket is False:
        return False
    print('Envfile from {}'.format(environment))
    for service_envs in env_files:
        env_path = service_envs['s3_path']
        destination = service_envs['local_path']
        state = download_env_s3(bucket.strip(), env_path.strip(), destination.strip())
        if state is True:
            continue
        print('Warn|envs3path:{}/{}|download env file from s3 have failed'.format(bucket, env_path))
        if state == 404:
            print('Try download from cmdb')
            state = download_env_cmdb(arg_service, environment, destination)
            if state is True:
                continue
            print('Error|envfile download from cmdb has been failed')
        return False
    else:
        return True

def codeartifact(service_data):
    artifact_repos = service_data['code']
    if artifact_repos:
        language = service_data['language']
        if language in ('python', 'python3'):
            tool = 'pip'
        elif language in ('javascript', 'typescript'):
            tool = 'npm'
        elif language in ('java'):
            tool = 'gradle'
        else:
            print('Error:language:{}|not match language, repo tool not get'.format(language))
            return False
        for artifact_repo in artifact_repos:
            state = login_codeartifact(artifact_repo, tool)
            if state is not True:
                print('Error:codeartifact login failed')
                return False
    else:
        print("Info: No codeartifact config in cmdb, don't login aws codeartifact")

def main():
    if arg_total_switch is True:
        request_api = '{}/{}'.format('services', arg_service)
        service_data = get_cmdb(request_api)
        if not service_data:
            print('Error: {} get build data failed'.format(arg_service))
            exit(3)

        # download env
        service_data_envs = service_data['envs']
        if service_data_envs:
            if arg_no_envfile is False:
                state = download_env(service_data_envs)
                if not state:
                    exit(3)
            else:
                print('Info: --no-envfile {}|not download envfile'.format(arg_no_envfile))
        else:
            state = download_env_cmdb2(arg_service, environment)
            if state is not True:
                exit(3)

        # login codeartifact
        #if not codeartifact(service_data):
        #    exit(3)

    # download custom envfile
    if arg_envfile_from:
        for conf_path in arg_envfile_from:
            source, destination = conf_path.split('|')
            if source.startswith('s3'):
                bucket, env_path = get_s3path_bucket_object(source)
                print('bucket:{}|env_path:{}|destination'.format(bucket, env_path, destination))
                state = download_env_s3(bucket.strip(), env_path.strip(), destination.strip())
                if state is not True:
                    print('Error|s3path:{}/{}|download env file from s3 have failed'.format(bucket, env_path))
                    exit(3)
            else:
                env_content = get_cmdb(source, data_type='text')
                if env_content.strip():
                    with open(destination, 'w') as fd:
                        fd.write(env_content)
                    print('download cmdb {} env to {} successful'.format(source, destination))
                else:
                    print('env_content is empty|file_url:{}'.format(source))
                    exit(3)

    state = build(arg_command)
    if state is True:
        print('build successful')
    else:
        print('build failed')
        exit(3)

try:
    main()
except Exception:
    traceback.print_exc()
    exit(5)
