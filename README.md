## 易于使用，人性化的阿里云oss工具包

### 安装

```bash
pip install osscore
```

### 使用

#### OSSFileSystem

- access_key_id or define env OSS_ACCESS_KEY_ID
- access_key_secret or define env OSS_ACCESS_KEY_SECRET
- endpoint or define env OSS_ENDPOINT
- token

##### 上传文件

```python
from osscore import OSSFileSystem

OSSFileSystem().upload("bucket_name", "local_path", "key")
```

##### 下载文件

> local_path 不写会返回 temp file

```python
from osscore import OSSFileSystem

OSSFileSystem().download("bucket_name", "key", "local_path")
```