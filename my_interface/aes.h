#include <stdio.h>
#include <string.h>
#include <unistd.h>
 
#include <openssl/pem.h>
#include <openssl/aes.h>
// #include "openssl/bio.h"
// #include "openssl/evp.h"

/*
这个是你自己写的一个十六字节的秘钥,aes加密解密都用这同一个
命令：find /usr/include/ -name *.h | xargs grep 'AES_BLOCK_SIZE'
结果：/usr/include/openssl/aes.h:# define AES_BLOCK_SIZE 16
//256下 key为秘钥32 iv为偏移16
*/
 ///usr/include/openssl/aes.h:# define AES_BLOCK_SIZE 16 

#define AES_BITS 10240
#define MSG_LEN 10240
 
/**********************************************************
函数名：getlen           
参数：char *str        --字符串地址
返回值：int            --字符串长度
说明：输入字符串地址获取字符串长度
***********************************************************/
int getlen(char *str) {
    int i = 0;
    while (str[i] != '\0') {
        i++;
    }
    return i;
}
/**********************************************************
函数名：PKCS7Padding          
参数：unsigned char *str      --字符串地址
返回值：int                   --正向测试填充后的字符串长度
说明：对初始数据进行PKCS7Padding填充
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
函数名：DePKCS7Padding         
参数：unsigned char *p    --字符串地址
返回值：int               --反填充个数
说明：对明文进行PKCS7Padding填充反填充(去除后面的填充乱码)
***********************************************************/
int DePKCS7Padding(unsigned char *str)
{
 	 int remain,i;

 	 while (*str != '\0'){str++;}  //定位到\0
 	 str--;
 	 remain = *str;//读取填充的个数
 	 //printf("remain = %d\n",remain); 
 	 //定位到最前面的填充数
 	 for(i=0;i<remain;i++){str--;}
 	 str++;
 	 *str = '\0';//截断
 	 return remain;
}
/**********************************************************
函数名：aes_encrypt
参数：char* str_in     --输入字符串地址
参数：char* out        --输出字符串地址
参数：char* key        --秘钥key 32位
参数：char* iv         --偏移key 16位
返回值:int             --0失败  1成功
说明：输入"明文"字符串地址  输出ase加密后的"密文"的字符串(乱码不可读)到地址 
***********************************************************/
int aes_encrypt(char* str_in, char* str_out,char *key)
{
  	//检测是否有 输入 KEY 输入  有其1为NULL则退出
    if (!str_in || !key || !str_out) return 0;
    
    //抽取数据
    char aes_encode_temp[1024]; 
    strcpy(aes_encode_temp,str_in);


    //进行PCK7填充 获取填充后长度
    int len = PKCS7Padding((unsigned char*)aes_encode_temp);
    //printf("PKCS7Padding str : %s\n",aes_encode_temp); //打印填充后的数据
 	
    //通过自己的秘钥获得一个aes秘钥以供下面加密使用
    AES_KEY aes;
	
    if (AES_set_encrypt_key((unsigned char*)key, 256, &aes) < 0)//256表示32位字符秘钥
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
    //加密接口，使用之前获得的aes秘钥
    //AES_ecb_encrypt((unsigned char*)aes_encode_temp, (unsigned char*)str_out, &aes,  AES_ENCRYPT);
    return 1;
}
 
/**********************************************************
函数名：aes_decrypt
参数：char* str_in     --输入字符串地址
参数：char* str_out    --输出字符串地址
参数：char* key        --秘钥key 32位
参数：char* iv         --偏移key 16位
返回值:int             --0失败  1成功
说明：输入"密文"字符串地址  输出ase解密后的"明文"后的字符串(乱码不可读)到地址 
***********************************************************/
int aes_decrypt(char* str_in, char* str_out,char* key)
{
    if (!str_in || !key || ! str_out)    return 0; 
 

   
    //通过自己的秘钥获得一个aes秘钥以供下面解密使用，128表示16字节
    AES_KEY aes; 

    if (AES_set_decrypt_key((unsigned char*)key, 256, &aes) < 0)//成功返回0
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
    //这边是解密接口，使用之前获得的aes秘钥
    //AES_ecb_encrypt((unsigned char*)aes_encode_temp, (unsigned char*) str_out, &aes,  AES_DECRYPT);
    DePKCS7Padding(str_out);

    return 1;
}
 
 /**********************************************************
函数名：base64_encode
参数：char* in_str    --输入字符串地址
参数：char* out_str    --输出字符串地址
返回值:int             --0失败  成功返回编号的字节数
说明：对in_str进行base64编码 输出到out_str
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
函数名：base64Decode
参数：char* in_str     --输入字符串地址
参数：char* out_str    --输出字符串地址
返回值:int             --0
说明：对str_in进行base64编码 输出到out_str
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
函数名：main
使用方法：
./aes 数据 例子：./aes test
***********************************************************/
/*int main(int argc, char *argv[])
{
   
    //char str[100]="shiyishi";
 	char str[100]="{\"query\":\"mac\",\"mac\":\"902b34cdb4e0\"}";
 	printf("------------------------正向测试-----------------------------\n");
    //aes加密
    printf("-------------------------------------------------------\n");
    char aes_encode_out[1024];  
    bzero(aes_encode_out, 1024);
    aes_encrypt(str, aes_encode_out,key);
    printf("加密-密文:\n%s\n", aes_encode_out); //打印密文
    printf("-------------------------------------------------------\n");
    //base64加密
    char base64_encode_out[1024] = {0};
    bzero(base64_encode_out, 1024);
    base64_encode(aes_encode_out, base64_encode_out);
    printf("编码-64:\n%s\n", base64_encode_out);
    printf("-------------------------------------------------------\n");

    printf("------------------------逆向测试-----------------------------\n");
    //base64解密
    char base64_decode_out[1024] = {0};
    bzero(base64_decode_out, 1024);
    base64Decode(base64_encode_out, base64_decode_out);


    printf("解码-64:\n%s\n", base64_decode_out);
    printf("-------------------------------------------------------\n");


    //aes解密
    char aes_decode_out[1024] = {0};
    bzero(aes_decode_out, 1024);

    aes_decrypt(base64_decode_out, aes_decode_out,key);

    printf("解密-明文:\n%s\n", aes_decode_out);
    printf("-------------------------------------------------------\n");
    return 0;
}*/

