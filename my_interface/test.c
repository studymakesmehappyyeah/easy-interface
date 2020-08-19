#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "aes.h"
#include "sha1.c"
#include "md5.c"


int main(){
	char *url="http://192.168.103.9:6091/api/v1/user/auth-query";
	int i,j;
	unsigned char key[64]={0};
	snprintf(key,sizeof(key),"weimeng");
	//对key进行md5加密 并转为大写
	unsigned char decrypt[16];    
	MD5_CTX md5;
	MD5Init(&md5);         		
	MD5Update(&md5,key,strlen((char *)key));
	MD5Final(&md5,decrypt);
	
	//key要大写
	for(i=0;i<16;i++){
		sprintf(key+2*i,"%02X",decrypt[i]);
	}

	//厂商
	char manufacturer[32];
	snprintf(manufacturer,sizeof(manufacturer),"weimeng");
	char *newstr1=(char *)malloc(2048);

	//加密的数据
	char mac[128]={0};
	char mac_str[32]={0};
	snprintf(mac_str,sizeof(mac_str),"902b34cdb4e0");
	snprintf(mac,sizeof(mac),"{\"query\":\"mac\",\"mac\":\"%s\"}",mac_str);
	//char *mac="shiyishi";
	unsigned char aes_encode_out[1024];  
    bzero(aes_encode_out, 1024);
    aes_encrypt(mac, aes_encode_out,key);	
	printf("strlen%d\n",strlen(aes_encode_out));

	//加密完后 转为二进制的形式
	unsigned char xs[1024] = {0};
    for(i=0;i<strlen(aes_encode_out);i++){
		sprintf(xs+i*2,"%02x",aes_encode_out[i]);
	}
	
	
	//随机10字符串
	int flag;
	char random_str[11]={0};
	srand((unsigned) time(NULL ));

	for (i = 0; i < 10; i++)
	{
		flag = rand() % 2;
		switch (flag)
		{
		case 0:
			random_str[i] = '0' + rand() % 10;
			break;
		case 1:
			random_str[i] = 'a' + rand() % 26;
			break;
		default:
			random_str[i] = 'x';
			break;
		}
	}
	random_str[10] = '\0';
	
	//时间戳
	time_t t;
	t=time(0);	
	char timestamp[10];
	sprintf(timestamp,"%d",t);

	//排序
	//先字典序排序
	char *arr[4];
	arr[0]=manufacturer;
	arr[1]=xs;
	arr[2]=random_str;
	arr[3]=timestamp;

	for(i=0;i<4;i++){
		for(j=i+1;j<4;j++){
			if(strcmp(arr[i],arr[j])>0){ //升序 
				char *p=arr[i];
				arr[i]=arr[j];
				arr[j]=p;
			}
		}
	}
	//排序后 SHA1加密 并转小写
	char *dic_str=(char *)malloc(strlen(arr[0])+strlen(arr[1])+strlen(arr[2])+strlen(arr[3]));
	sprintf(dic_str,"%s%s%s%s",arr[0],arr[1],arr[2],arr[3]);
	char res[100];
	StrSHA1(dic_str,strlen(dic_str),res);
	
	free(dic_str);
	dic_str=NULL;
	
	for(i=0;i<strlen(res);i++){
		res[i]=tolower(res[i]);
	}

	//拼接在一起
	sprintf(newstr1,"%s?manufacturer=%s&params=%s&nonce=%s&timestamp=%s&signature=%s",url,manufacturer,xs,random_str,timestamp,res);
	printf("%s\n",newstr1);
	free(newstr1);
	newstr1=NULL;
}
