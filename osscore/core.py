#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @author: similraface
# @contact: similarface@gmail.com
# @software: PyCharm
# @file: core.py
# @time: 2022/9/22 2:59 下午
# @desc:
import json
import os
import time
import oss2
from itertools import islice

import tempfile
from aliyunsdkcore.client import AcsClient
from aliyunsdksts.request.v20150401.AssumeRoleRequest import AssumeRoleRequest


class STSSystem:
    def __init__(self, access_key_id=None, access_key_secret=None, endpoint=None):
        self.access_key = access_key_id or os.environ.get("OSS_ACCESS_KEY_ID")
        self.secret_key = access_key_secret or os.environ.get('OSS_ACCESS_KEY_SECRET')
        self.endpoint = endpoint or os.environ.get("cn-beijing")
        self.client = None

    def create_client(self):
        if self.client is None:
            self.client = AcsClient(self.access_key, self.secret_key, self.endpoint)
        return self.client

    def assume_role(self, role_arn, policy=None, session_name=None, duration_seconds=3600, accept_format='json'):
        client = self.create_client()
        request = AssumeRoleRequest()
        request.set_accept_format(accept_format)
        request.set_DurationSeconds(duration_seconds)
        request.set_RoleArn(role_arn)
        if policy is not None:
            request.set_Policy(policy)
        session_name = str(time.time()) if session_name is None else session_name
        request.set_RoleSessionName(session_name)
        # 发起请求，并得到响应。
        response = client.do_action_with_exception(request)
        return json.loads(response.decode('utf-8'))

    def generate_credentials(self, role_arn, policy=None, session_name=None, duration_seconds=3600):
        return self.assume_role(role_arn=role_arn, policy=policy, session_name=session_name, duration_seconds=duration_seconds)['Credentials']


class OSSFileSystem:
    def __init__(self, access_key=None, secret_key=None, token=None, endpoint=None):
        self.access_key = access_key or os.environ.get("OSS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.environ.get('OSS_ACCESS_KEY_SECRET')
        self.token = token
        self.endpoint = endpoint or os.environ.get("OSS_ENDPOINT")

    def auth(self):
        if self.token is None:
            if self.access_key is None or self.secret_key is None:
                return oss2.AnonymousAuth()
            return oss2.StsAuth(self.access_key, self.secret_key, self.token)
        else:
            return oss2.auth(self.access_key, self.secret_key)

    def bucket(self, bucket_name, **kwargs) -> oss2.Bucket:
        print(bucket_name, self.endpoint)
        return oss2.Bucket(self.auth(), self.endpoint, bucket_name, **kwargs)

    def upload(self, bucket_name, local_path, key):
        """
        上传文件
        :param bucket_name:
        :param key:
        :param local_path:
        :return:
        """
        bucket_obj = self.bucket(bucket_name=bucket_name)
        bucket_obj.put_object_from_file(key, local_path)

    def upload_str(self, bucket_name, str_content, key):
        """
        上传字符串
        :param bucket_name:
        :param str_content: str
        :param key:
        :return:
        """
        return self.upload_object(bucket_name=bucket_name, content=str_content, key=key)

    def upload_byte(self, bucket_name, byte_content, key):
        """
        上传Bytes
        :param bucket_name:
        :param byte_content: b'Hello OSS'
        :param key:
        :return:
        """
        return self.upload_object(bucket_name=bucket_name, content=byte_content, key=key)

    def upload_unicode(self, bucket_name, unicode_content, key):
        """
        上传Unicode字符
        :param bucket_name:
        :param byte_content: u'Hello OSS'
        :param key:
        :return:
        """
        return self.upload_object(bucket_name=bucket_name, content=unicode_content, key=key)

    def upload_streaming(self, bucket_name, stream_content, key):
        """
        上传网络流
        :param bucket_name:
        :param stream_content:
        :param key:
        :return:
        """
        return self.upload_object(bucket_name=bucket_name, content=stream_content, key=key)

    def upload_object(self, bucket_name, content, key):
        bucket = self.bucket(bucket_name)
        result = bucket.put_object(key, content)
        return result

    def download(self, bucket_name, key, local_path=None) -> str:
        """
        下载文件
        :param bucket_name:
        :param key:
        :param local_path:
        :return: 下载文件的绝对地址
        """
        local_path = local_path if local_path else tempfile.mktemp()
        bucket = self.bucket(bucket_name=bucket_name)
        bucket.get_object_to_file(key, local_path)
        return os.path.abspath(local_path)

    def list_bucket(self, bucket_name):
        bucket_obj_list = []
        bucket = self.bucket(bucket_name=bucket_name)
        for b in islice(oss2.ObjectIterator(bucket), 10):
            bucket_obj_list.append(b.key)
            print(b.key)
        return bucket_obj_list

    def rm(self, bucket_name, key):
        bucket = self.bucket(bucket_name=bucket_name)
        # <yourObjectName>表示删除OSS文件时需要指定包含文件后缀，不包含Bucket名称在内的完整路径，例如abc/efg/123.jpg。
        bucket.delete_object(key)

    def create_bucket(self, bucket_name):
        raise RuntimeError("不被允许")
        bucket = self.bucket(bucket_name=bucket_name)
        # 创建存储空间。
        # 如果需要在创建存储空间时设置存储类型、存储空间访问权限、数据容灾类型，请参考以下代码。
        # 以下以配置存储空间为标准存储类型，访问权限为私有，数据容灾类型为同城冗余存储为例。
        # bucketConfig = oss2.models.BucketCreateConfig(oss2.BUCKET_STORAGE_CLASS_STANDARD, oss2.BUCKET_DATA_REDUNDANCY_TYPE_ZRS)
        # bucket.create_bucket(oss2.BUCKET_ACL_PRIVATE, bucketConfig)
        bucket.create_bucket()

    def upload_object_append(self, bucket_name):
        # 如需在追加上传时设置相关Headers，请参考如下示例代码。
        # headers = dict()
        # 指定该Object的网页缓存行为。
        # headers['Cache-Control'] = 'no-cache'
        # 指定该Object被下载时的名称。
        # headers['Content-Disposition'] = 'oss_MultipartUpload.txt'
        # 指定该Object的内容编码格式。
        # headers['Content-Encoding'] = 'utf-8'
        # 该请求头用于检查消息内容是否与发送时一致。
        # headers['Content-MD5'] = 'ohhnqLBJFiKkPSBO1eNaUA=='
        # 指定过期日期。
        # headers['Expires'] = 'Wed, 08 Jul 2022 16:57:01 GMT'
        # 指定Object的访问权限ACL。此处指定为OBJECT_ACL_PRIVATE，表示私有访问权限。
        # headers['x-oss-object-acl'] = oss2.OBJECT_ACL_PRIVATE
        # 指定追加上传时是否覆盖同名Object。
        # headers['x-oss-forbid-overwrite'] = 'true'
        # 指定服务器端加密方式。此处指定为OSS完全托管密钥进行加密（SSE-OSS）。
        # headers[OSS_SERVER_SIDE_ENCRYPTION] = SERVER_SIDE_ENCRYPTION_AES256
        # 指定Object的存储类型。
        # headers['x-oss-storage-class'] = oss2.BUCKET_STORAGE_CLASS_STANDARD
        # 创建AppendObject时可以添加x-oss-meta-*，继续追加时不可以携带此参数。如果配置以x-oss-meta-*为前缀的参数，则该参数视为元数据。
        # headers['x-oss-meta-author'] = 'Alice'
        # result = bucket.append_object(exampledir/exampleobject.txt, 0, 'content of first append', headers=headers)

        # 设置首次上传的追加位置（Position参数）为0。
        # 填写不能包含Bucket名称在内的Object完整路径，例如exampledir/exampleobject.txt。
        # result = bucket.append_object('exampledir/exampleobject.txt', 0, 'content of first append')
        # # 如果不是首次上传，可以通过bucket.head_object方法或上次追加返回值的next_position属性，获取追加位置。
        # bucket.append_object('<yourObjectName>', result.next_position, 'content of second append')
        pass


