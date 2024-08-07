//montando o megazord
/*
 * lista de comandos
 * sha256.reset()
 * sha256.update(vetorParaTirarHash,tamanhoDoVetor)
 * sha256.finalize(vetorQueArmazenaAHash,tamanhoDoVetor)
 */

 /*
  * aes128.setkey(vetorDaChave,tamanhoEmBytesDaChave) //PRIMEIRO DEFINIR ESSE!!!!!
  * aes128.encryptBlock(vetorDeSaida,vetorDeEntrada)
  * aes128.decryptBlock(vetorDeSaida,vetorDeEntrada)
  */
//adicionar biblioteca "Crypto" do Dr. Branom Wiley  https://rweather.github.io/arduinolibs/index.html
//adicionar manualmente biblioteca (via arquivo .zip) do ArduinoDES http://spaniakos.github.io/ArduinoDES/index.html


 
#include <Crypto.h>
#include <SHA256.h>
#include <string.h>
#include <AES.h>
#include <DES.h>
#include <string.h>
#include <stdio.h>

#include <SPI.h>
#include <mcp2515.h>

#define HASH_SIZE 32 // tamanho maximo da hash -> 32 bytes!!!. vai ficar num vetor de unsigned char
#define MKRCAN_MCP2515_INT_PIN 2

static const unsigned char chavePrivada3DES[]="0123456789ABCDEF01234567"; // 24 bytes. Requisito da biblioteca
static const unsigned char chavePrivadaAES[]="0123456789ABCDEF"; //128 bits

unsigned int ids_radar[]   = {0x200,0x201,0x202,0x203} ; // #0x200 e 0x200->radar_cfg; 0x202 e 0x203->radar_status
unsigned int ids_cluster[] = {0x600,0x701,0x702} ; // #0x600->cluster_status; 0x701 e 0x702->cluster_general;
unsigned int ids_object[]  = {0x60A,0x60B,0x60C,0x60D,0x60}; // #0x60A->obj_status; 0x60B e 0x60C->obj_general;0x60D e 0x60E->obj_quality
unsigned char mensagemReferencia[]="12345678"; // cada bloco é 1 byte (pensando no payload CAN). Mas a biblioteca aceita qualquer tamanho de entrada

SHA256 sha256;// é um objeto da classe Hash
AES128 aes128;
DES des;
MCP2515 mcp2515(53); // CHIP SELECT PIN digitalPin->53 (on arduino mega)

bool verificaOpcoes(unsigned char mensagem){
  return (mensagem==0 || mensagem==1); //retorna true se uma das opcoes for atendida
}

unsigned char* hashSHA256(unsigned char *payload,unsigned char tamanho){ //TRUNCADO EM TAMANHO!!!
  unsigned char *valorHash= (unsigned char *) malloc( (unsigned long) tamanho*sizeof(unsigned char));
  sha256.reset();
  sha256.update(payload, (unsigned long) tamanho);
  sha256.finalize(valorHash,(unsigned long) tamanho); 
  return valorHash;// tamamho maximo de tamanho. Ele será truncado
}

unsigned char* encryptAES(unsigned char *payload){// somente confidencialidade em can FD
  unsigned char *valorCifrado= (unsigned char *) malloc(16*sizeof(unsigned char));
  aes128.setKey(chavePrivadaAES,16);
  aes128.encryptBlock(valorCifrado,payload);
  return valorCifrado;// tamamho maximo de 16 bytes
}

unsigned char* decryptAES(unsigned char *payload){// somente confidencialidade em can FD
  unsigned char *puroTexto= (unsigned char *) malloc(16*sizeof(unsigned char));
  aes128.setKey(chavePrivadaAES,16);
  aes128.decryptBlock(puroTexto,payload);
  return puroTexto;// tamamho maximo de 16 bytes
}

unsigned char* encrypt3DES(unsigned char *payload){// somente confidencialidade em can tradicional
  unsigned char *valorCifrado= (unsigned char *) malloc(8*sizeof(unsigned char));//8 bytes
  des.tripleEncrypt(valorCifrado, payload, chavePrivada3DES);
  return valorCifrado;// tamamho maximo de 8 bytes
}

unsigned char* decrypt3DES(unsigned char *payload){// somente confidencialidade em can tradicional
  unsigned char *puroTexto= (unsigned char *) malloc(8*sizeof(unsigned char));//8 bytes
  des.tripleDecrypt(puroTexto, payload, chavePrivada3DES);
  return puroTexto;// tamanho maximo de 8 bytes
}

unsigned char* cryptoMessagesCAN(unsigned char *msg, unsigned char canFD, unsigned char confidencialidade, unsigned char integridade ){
  if(!verificaOpcoes(confidencialidade) || !verificaOpcoes(integridade) || !verificaOpcoes(canFD)){
    Serial.println("Opcao inválida");
    return "Opcao inválida";
  }
  unsigned char len = (unsigned char) strlen(msg);
  unsigned char opcao=(canFD<<2)|(confidencialidade<<1)|(integridade<<0);  
  switch(opcao){
    case 0://normal
      return msg;
    break;
    
    case 1://integridade
      return hashSHA256(msg,len);
    break;
    
    case 2://confidencialidade
      return encrypt3DES(msg); 
    break;
    
    case 3:
    {//confidencialdade e integridade. AQUI SERÁ UTILIZADA A CIFRA DE VERNAM (o OTP). Falta implementá-lo. Enquanto isso, usaremos o 3DES!!!!
      unsigned char *tempMsg = encrypt3DES(msg);//8 bytes
      unsigned char *tempHash = hashSHA256(tempMsg,(unsigned char)strlen(tempMsg));//8 bytes pq o retorno do 3des éh 8 bytes
      unsigned char *msgEhash = (unsigned char *) malloc(16*sizeof(unsigned char));
      for(char i=0; i<16;i++){
        if(i<8)
          msgEhash[i]=tempMsg[i];
        
        else
          msgEhash[i]=tempHash[i-8];
      }
      return msgEhash;
    }
    break;   
    case 4://canfd e normal
      return msg;
    break;
    
    case 5://canfd e integridade
      return hashSHA256(msg,HASH_SIZE);
    break;
    
    case 6://canfd e confidencialidade
      return encryptAES(msg); 
    break;
    
    case 7:{//canfd ,confidencialdade e integridade
      unsigned char *tempMsg = encryptAES(msg);//16 bytes
      unsigned char *tempHash = hashSHA256(tempMsg,(unsigned char)strlen(tempMsg));//16 bytes pq o retorno do aes éh 16 bytes
      unsigned char *msgEhash = (unsigned char *) malloc(32*sizeof(unsigned char));
      for(char i=0; i<32;i++){
        if(i<16)
          msgEhash[i]=tempMsg[i];
        
        else
          msgEhash[i]=tempHash[i-16];          
      }
    }
    break;  
    
  }
  
}

void setup() {
  while (!Serial);
  Serial.begin(9600);
  (!mcp2515.reset())?Serial.println("reset ok!"):Serial.println("reset falhou");
  (!mcp2515.setBitrate(CAN_500KBPS,MCP_8MHZ))?Serial.println("bitrate ok!"):Serial.println("bitrate falhou!");
  (!mcp2515.setNormalMode())?Serial.println("modo definido ok"):Serial.println("modo definido falha");
  delay(1000);

}

/*
 * unsigned int ids_radar[]   = {0x200,0x201,0x202,0x203} ; // #0x200 e 0x200->radar_cfg; 0x202 e 0x203->radar_status
unsigned int ids_cluster[] = {0x600,0x701,0x702} ; // #0x600->cluster_status; 0x701 e 0x702->cluster_general;
unsigned int ids_object[]  = {0x60A,0x60B,0x60C,0x60D,0x60}; // #0x60A->obj_status; 0x60B e 0x60C->obj_general;0x60D e 0x60E->obj_quality
unsigned char mensagemReferencia[]="12345678"; // cada bloco é 1 byte (pensando no payload CAN). Mas a biblioteca aceita qualquer tamanho de entrada
 */
/*
struct can_frame {
    canid_t can_id;  // 32 bit CAN_ID + EFF/RTR/ERR flags 
    __u8    can_dlc; // frame payload length in byte (0 .. CAN_MAX_DLEN)
    __u8    data[CAN_MAX_DLEN] __attribute__((aligned(8)));
};
*/ 
   

void loop() {
  unsigned char i=0;
  char texto[256]={};
  
  for(unsigned char j=0;j<8;j++){
    unsigned char *msgAdulterada = cryptoMessagesCAN(mensagemReferencia,(j&4)>>2,(j&2)>>1,(j&1)>>0);
    unsigned char tamMsg = (unsigned char)strlen(msgAdulterada);
    for(i=0;i<sizeof(ids_radar)/sizeof(ids_radar[0]);i++){
      sprintf(texto,"Mensagem referencia:%s\nMensagem a ser enviada:\nID:%d\tDLC:%d\tPayload:%s",mensagemReferencia,ids_radar[i],(int)tamMsg,msgAdulterada);
      Serial.println(texto);
      if(tamMsg<8){
      struct can_frame mensagem = {ids_radar[i], tamMsg, msgAdulterada};
      mcp2515.sendMessage(&mensagem);
      }
      else{
       for(unsigned char k=0;k<tamMsg/8;k++){
        char temporario[9]={};
        strncpy(temporario,temporario,8);// continuar daqui!!
        temporario[8]='\0';
        struct can_frame mensagem = {ids_radar[i], 8, msgAdulterada};
        mcp2515.sendMessage(&mensagem);
       }
        
      }
    }
    for(i=0;i<sizeof(ids_cluster)/sizeof(ids_cluster[0]);i++){
      
    }
    for(i=0;i<sizeof(ids_object)/sizeof(ids_object[0]);i++){
      
    }
  }
  
  delay(1500);

}
