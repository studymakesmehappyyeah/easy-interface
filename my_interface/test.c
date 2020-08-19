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
	//��key����md5���� ��תΪ��д
	unsigned char decrypt[16];    
	MD5_CTX md5;
	MD5Init(&md5);         		
	MD5Update(&md5,key,strlen((char *)key));
	MD5Final(&md5,decrypt);
	
	//keyҪ��д
	for(i=0;i<16;i++){
		sprintf(key+2*i,"%02X",decrypt[i]);
	}

	//����
	char manufacturer[32];
	snprintf(manufacturer,sizeof(manufacturer),"weimeng");
	char *newstr1=(char *)malloc(2048);

	//���ܵ�����
	char mac[128]={0};
	char mac_str[32]={0};
	snprintf(mac_str,sizeof(mac_str),"902b34cdb4e0");
	snprintf(mac,sizeof(mac),"{\"query\":\"mac\",\"mac\":\"%s\"}",mac_str);
	//char *mac="shiyishi";
	unsigned char aes_encode_out[1024];  
    bzero(aes_encode_out, 1024);
    aes_encrypt(mac, aes_encode_out,key);	
	printf("strlen%d\n",strlen(aes_encode_out));

	//������� תΪ�����Ƶ���ʽ
	unsigned char xs[1024] = {0};
    for(i=0;i<strlen(aes_encode_out);i++){
		sprintf(xs+i*2,"%02x",aes_encode_out[i]);
	}
	
	
	//���10�ַ���
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
	
	//ʱ���
	time_t t;
	t=time(0);	
	char timestamp[10];
	sprintf(timestamp,"%d",t);

	//����
	//���ֵ�������
	char *arr[4];
	arr[0]=manufacturer;
	arr[1]=xs;
	arr[2]=random_str;
	arr[3]=timestamp;

	for(i=0;i<4;i++){
		for(j=i+1;j<4;j++){
			if(strcmp(arr[i],arr[j])>0){ //���� 
				char *p=arr[i];
				arr[i]=arr[j];
				arr[j]=p;
			}
		}
	}
	//����� SHA1���� ��תСд
	char *dic_str=(char *)malloc(strlen(arr[0])+strlen(arr[1])+strlen(arr[2])+strlen(arr[3]));
	sprintf(dic_str,"%s%s%s%s",arr[0],arr[1],arr[2],arr[3]);
	char res[100];
	StrSHA1(dic_str,strlen(dic_str),res);
	
	free(dic_str);
	dic_str=NULL;
	
	for(i=0;i<strlen(res);i++){
		res[i]=tolower(res[i]);
	}

	//ƴ����һ��
	sprintf(newstr1,"%s?manufacturer=%s&params=%s&nonce=%s&timestamp=%s&signature=%s",url,manufacturer,xs,random_str,timestamp,res);
	printf("%s\n",newstr1);
	free(newstr1);
	newstr1=NULL;
}
