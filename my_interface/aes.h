#include <stdio.h>
#include <string.h>
#include <unistd.h>
 
#include <openssl/pem.h>
#include <openssl/aes.h>
// #include "openssl/bio.h"
// #include "openssl/evp.h"

/*
��������Լ�д��һ��ʮ���ֽڵ���Կ,aes���ܽ��ܶ�����ͬһ��
���find /usr/include/ -name *.h | xargs grep 'AES_BLOCK_SIZE'
�����/usr/include/openssl/aes.h:# define AES_BLOCK_SIZE 16
//256�� keyΪ��Կ32 ivΪƫ��16
*/
 ///usr/include/openssl/aes.h:# define AES_BLOCK_SIZE 16 

#define AES_BITS 10240
#define MSG_LEN 10240
 
/**********************************************************
��������getlen           
������char *str        --�ַ�����ַ
����ֵ��int            --�ַ�������
˵���������ַ�����ַ��ȡ�ַ�������
***********************************************************/
int getlen(char *str) {
    int i = 0;
    while (str[i] != '\0') {
        i++;
    }
    return i;
}
/**********************************************************
��������PKCS7Padding          
������unsigned char *str      --�ַ�����ַ
����ֵ��int                   --�������������ַ�������
˵�����Գ�ʼ���ݽ���PKCS7Padding���
***********************************************************/
int PKCS7Padding(unsigned char *str)
{
    int remain, i;
    int len=getlen(str);
    remain = 16 - len%16;
    //printf("remain = %d\n",remain);
    for(i=0; i<remain; i++)
    {
        str[len+i] = remain;
        //printf("str[len+i]= %d\n",str[len+i]);
    }
   	str[len+i] = '\0';
    
    return len + remain;
}
/**********************************************************
��������DePKCS7Padding         
������unsigned char *p    --�ַ�����ַ
����ֵ��int               --��������
˵���������Ľ���PKCS7Padding��䷴���(ȥ��������������)
***********************************************************/
int DePKCS7Padding(unsigned char *str)
{
 	 int remain,i;

 	 while (*str != '\0'){str++;}  //��λ��\0
 	 str--;
 	 remain = *str;//��ȡ���ĸ���
 	 //printf("remain = %d\n",remain); 
 	 //��λ����ǰ��������
 	 for(i=0;i<remain;i++){str--;}
 	 str++;
 	 *str = '\0';//�ض�
 	 return remain;
}
/**********************************************************
��������aes_encrypt
������char* str_in     --�����ַ�����ַ
������char* out        --����ַ�����ַ
������char* key        --��Կkey 32λ
������char* iv         --ƫ��key 16λ
����ֵ:int             --0ʧ��  1�ɹ�
˵��������"����"�ַ�����ַ  ���ase���ܺ��"����"���ַ���(���벻�ɶ�)����ַ 
***********************************************************/
int aes_encrypt(char* str_in, char* str_out,char *key)
{
  	//����Ƿ��� ���� KEY ����  ����1ΪNULL���˳�
    if (!str_in || !key || !str_out) return 0;
    
    //��ȡ����
    char aes_encode_temp[1024]; 
    strcpy(aes_encode_temp,str_in);


    //����PCK7��� ��ȡ���󳤶�
    int len = PKCS7Padding((unsigned char*)aes_encode_temp);
    //printf("PKCS7Padding str : %s\n",aes_encode_temp); //��ӡ���������
 	
    //ͨ���Լ�����Կ���һ��aes��Կ�Թ��������ʹ��
    AES_KEY aes;
	
    if (AES_set_encrypt_key((unsigned char*)key, 256, &aes) < 0)//256��ʾ32λ�ַ���Կ
    {
        return 0;
    }
 	int round=len/16;
	int i;
	for(i=0;i<round;i++){
		int temp;
		temp=i*16;
		AES_ecb_encrypt((unsigned char*)(aes_encode_temp+temp), (unsigned char*)(str_out+temp), &aes,  AES_ENCRYPT);
	}
    //���ܽӿڣ�ʹ��֮ǰ��õ�aes��Կ
    //AES_ecb_encrypt((unsigned char*)aes_encode_temp, (unsigned char*)str_out, &aes,  AES_ENCRYPT);
    return 1;
}
 
/**********************************************************
��������aes_decrypt
������char* str_in     --�����ַ�����ַ
������char* str_out    --����ַ�����ַ
������char* key        --��Կkey 32λ
������char* iv         --ƫ��key 16λ
����ֵ:int             --0ʧ��  1�ɹ�
˵��������"����"�ַ�����ַ  ���ase���ܺ��"����"����ַ���(���벻�ɶ�)����ַ 
***********************************************************/
int aes_decrypt(char* str_in, char* str_out,char* key)
{
    if (!str_in || !key || ! str_out)    return 0; 
 

   
    //ͨ���Լ�����Կ���һ��aes��Կ�Թ��������ʹ�ã�128��ʾ16�ֽ�
    AES_KEY aes; 

    if (AES_set_decrypt_key((unsigned char*)key, 256, &aes) < 0)//�ɹ�����0
    {
        return 0;
    }
    
    char aes_encode_temp[1024]; 
    strcpy(aes_encode_temp,str_in);
  
    int len = getlen(aes_encode_temp);
	printf(" de len=%d\n",len);
    int round=len/16;
	int i;
	for(i=0;i<round;i++){
		int temp;
		temp=i*16;
		AES_ecb_encrypt((unsigned char*)(aes_encode_temp+temp), (unsigned char*)(str_out+temp), &aes,  AES_DECRYPT);
	}
    //����ǽ��ܽӿڣ�ʹ��֮ǰ��õ�aes��Կ
    //AES_ecb_encrypt((unsigned char*)aes_encode_temp, (unsigned char*) str_out, &aes,  AES_DECRYPT);
    DePKCS7Padding(str_out);

    return 1;
}
 
 /**********************************************************
��������base64_encode
������char* in_str    --�����ַ�����ַ
������char* out_str    --����ַ�����ַ
����ֵ:int             --0ʧ��  �ɹ����ر�ŵ��ֽ���
˵������in_str����base64���� �����out_str
***********************************************************/
int base64_encode(char *in_str, char *out_str)
{   
  	int in_len = getlen(in_str);
    BIO *b64 = NULL, *bio = NULL;
    BUF_MEM *bptr = NULL;
    size_t size = 0;
 
    if (in_str == NULL || out_str == NULL)
        return 0;
 
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
 
    BIO_write(bio, in_str, in_len);
    BIO_flush(bio);
 
    BIO_get_mem_ptr(bio, &bptr);
    memcpy(out_str, bptr->data, bptr->length);
    out_str[bptr->length] = '\0';
    size = bptr->length;
 
    BIO_free_all(bio);
   
    return size;
}
 /**********************************************************
��������base64Decode
������char* in_str     --�����ַ�����ַ
������char* out_str    --����ַ�����ַ
����ֵ:int             --0
˵������str_in����base64���� �����out_str
***********************************************************/
int base64Decode(char *in_str, char *out_str)
{
    int length =getlen(in_str);

    BIO *b64 = NULL;
    BIO *bmem = NULL;
   /* char *buffer = (char *)malloc(length);
    memset(buffer, 0, length);*/
    b64 = BIO_new(BIO_f_base64());
	/* if (!newLine) {
       BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }*/
    bmem = BIO_new_mem_buf(in_str, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, out_str, length);
    BIO_free_all(bmem);

    //strcpy(out_str,buffer);
    return 0;
}

/**********************************************************
��������main
ʹ�÷�����
./aes ���� ���ӣ�./aes test
***********************************************************/
/*int main(int argc, char *argv[])
{
   
    //char str[100]="shiyishi";
 	char str[100]="{\"query\":\"mac\",\"mac\":\"902b34cdb4e0\"}";
 	printf("------------------------�������-----------------------------\n");
    //aes����
    printf("-------------------------------------------------------\n");
    char aes_encode_out[1024];  
    bzero(aes_encode_out, 1024);
    aes_encrypt(str, aes_encode_out,key);
    printf("����-����:\n%s\n", aes_encode_out); //��ӡ����
    printf("-------------------------------------------------------\n");
    //base64����
    char base64_encode_out[1024] = {0};
    bzero(base64_encode_out, 1024);
    base64_encode(aes_encode_out, base64_encode_out);
    printf("����-64:\n%s\n", base64_encode_out);
    printf("-------------------------------------------------------\n");

    printf("------------------------�������-----------------------------\n");
    //base64����
    char base64_decode_out[1024] = {0};
    bzero(base64_decode_out, 1024);
    base64Decode(base64_encode_out, base64_decode_out);


    printf("����-64:\n%s\n", base64_decode_out);
    printf("-------------------------------------------------------\n");


    //aes����
    char aes_decode_out[1024] = {0};
    bzero(aes_decode_out, 1024);

    aes_decrypt(base64_decode_out, aes_decode_out,key);

    printf("����-����:\n%s\n", aes_decode_out);
    printf("-------------------------------------------------------\n");
    return 0;
}*/

