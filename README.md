# AWVS-Script

利用AWVS提供的Api编写的简单的脚本

API信息来源：https://www.sqlsec.com/2020/04/awvsapi.html

## 使用方法

修改`awvs_addres`和`awvs_api`，例如:

```python
awvs_address = 'https://127.0.0.1:13443'
awvs_api = '1986ad8c0a5b3df4d7028d5f3c06e936c749b43eb6b9e41e5926df14eb92c8077'
```

在命令行输入:

```shell
python awvs-script.py -h
```

可查看所有功能。