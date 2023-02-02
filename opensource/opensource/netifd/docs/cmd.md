```c
/* 开启vlan功能，并设置vlan id*/
echo '{"params":{"vlan":{"enable":true, "isp_name":"cmcc", "id":10}}}' | tmpcli -o 0x420e

/* 关闭vlan功能*/
echo '{"params":{"vlan":{"enable":false}}}' | tmpcli -o 0x420e


/* 查看vlan状态*/
tmpcli -o 0x420d {}

```

