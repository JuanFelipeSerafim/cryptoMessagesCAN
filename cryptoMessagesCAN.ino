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

/* Estrutura do frame CAN
struct can_frame {
    canid_t can_id;  // 32 bit CAN_ID + EFF/RTR/ERR flags ---> unsigned long==__u32==canid_t
    __u8    can_dlc; // frame payload length in byte (0 .. CAN_MAX_DLEN) --->unsigned char==__u8
    __u8    data[CAN_MAX_DLEN] __attribute__((aligned(8))); --->unsigned char==__u8
};
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
#include <stdlib.h>

#define HASH_SIZE 32 // tamanho maximo da hash -> 32 bytes!!!. vai ficar num vetor de unsigned char
#define MKRCAN_MCP2515_INT_PIN 2

static
const unsigned char chavePrivada3DES[] = "0123456789ABCDEF01234567"; // 24 bytes. Requisito da biblioteca
static
const unsigned char chavePrivadaAES[] = "0123456789ABCDEF"; //128 bits

unsigned int ids_radar[] = {
  0x200,
  0x201,
  0x202,
  0x203
}; // #0x200 e 0x200->radar_cfg; 0x202 e 0x203->radar_status

unsigned int ids_cluster[] = {
  0x600,
  0x701,
  0x702
}; // #0x600->cluster_status; 0x701 e 0x702->cluster_general;

unsigned int ids_object[] = {
  0x60A,
  0x60B,
  0x60C,
  0x60D,
  0x60E
}; // #0x60A->obj_status; 0x60B e 0x60C->obj_general;0x60D e 0x60E->obj_quality

unsigned char mensagemReferencia[] = "12345678"; // cada bloco é 1 byte (pensando no payload CAN). Mas a biblioteca aceita qualquer tamanho de entrada

// instancia os objetos das classes correspondentes
SHA256 sha256; // é um objeto da classe Hash
AES128 aes128;
DES des;
MCP2515 mcp2515(53); // CHIP SELECT PIN digitalPin->53 (on arduino mega)

//------------------------------------------ Funcoes que serão arduamente reutilizadas------------------------------------------ //

void printCANMessages(struct can_frame * mensagem) {
  /////////////////////////////////////////////////////////////////
  Serial.print(mensagem -> can_id, HEX); // print ID
  Serial.print(" ");
  Serial.print(mensagem -> can_dlc, HEX); // print DLC
  Serial.print(" ");

  for (int i = 0; i < mensagem -> can_dlc; i++) { // print the data
    Serial.print(mensagem -> data[i], HEX);
    Serial.print(" ");
  }
  Serial.println(" ");
  /////////////////////////////////////////////////////////////////
}

bool verificaOpcoes(unsigned char mensagem) {
  return (mensagem == 0 || mensagem == 1); //retorna true se uma das opcoes for atendida
}

uint8_t * hashSHA256(char * payload, uint8_t tamanho) { //TRUNCADO EM TAMANHO!!!
  uint8_t * valorHash = (uint8_t * ) malloc(tamanho * sizeof(uint8_t));
  sha256.reset();
  sha256.update(payload, tamanho);
  sha256.finalize(valorHash, tamanho);
  return valorHash; // tamanho maximo de "tamanho". Ele será truncado!
}

uint8_t * encryptAES(char * payload) { // somente confidencialidade em can FD
  uint8_t * valorCifrado = (uint8_t * ) malloc(16 * sizeof(uint8_t));
  aes128.setKey(chavePrivadaAES, 16);
  aes128.encryptBlock(valorCifrado, payload);
  return valorCifrado; // tamamho maximo de 16 bytes
}

uint8_t * decryptAES(char * payload) { // somente confidencialidade em can FD
  uint8_t * puroTexto = (uint8_t * ) malloc(16 * sizeof(uint8_t));
  aes128.setKey(chavePrivadaAES, 16);
  aes128.decryptBlock(puroTexto, payload);
  return puroTexto; // tamamho maximo de 16 bytes
}

uint8_t * encrypt3DES(char * payload) { // somente confidencialidade em can tradicional
  uint8_t * valorCifrado = (unsigned char * ) malloc(8 * sizeof(uint8_t)); //8 bytes
  des.tripleEncrypt(valorCifrado, payload, chavePrivada3DES);
  return valorCifrado; // tamamho maximo de 8 bytes
}

uint8_t * decrypt3DES(char * payload) { // somente confidencialidade em can tradicional
  uint8_t * puroTexto = (uint8_t * ) malloc(8 * sizeof(uint8_t)); //8 bytes
  des.tripleDecrypt(puroTexto, payload, chavePrivada3DES);
  return puroTexto; // tamanho maximo de 8 bytes
}

struct can_frame * prepararFrame(unsigned int id, uint8_t tamanho, uint8_t * payload) {
  struct can_frame * frame = (struct can_frame * ) malloc(sizeof(struct can_frame));
  frame -> can_id = id;
  frame -> can_dlc = tamanho;
  strcpy(frame -> data, payload);
  return frame;
}

void enviarMensagemCAN(uint8_t * msg, unsigned int id, char tamanho) {
  uint8_t temporario[9] = {};
  if (tamanho == -1) {
    strncpy(temporario, msg, 8);
    temporario[8] = '\0';
    struct can_frame * mensagem = prepararFrame(id, 8, temporario);
    printCANMessages(mensagem);
    mcp2515.sendMessage(mensagem);
    free(mensagem);
    delay(500);
  } else {
    strncpy(temporario, msg, tamanho);
    temporario[tamanho] = '\0';
    struct can_frame * mensagem = prepararFrame(id, tamanho, temporario);
    printCANMessages(mensagem);
    mcp2515.sendMessage(mensagem);
    free(mensagem);
    delay(500);
  }

}

//------------------------------------------------------------------------------------ //

//------------------------------------------ Funcao principal------------------------------------------ /

unsigned char * cryptoMessagesCAN(char * msg, unsigned char canFD, unsigned char confidencialidade, unsigned char integridade) {
  if (!verificaOpcoes(confidencialidade) || !verificaOpcoes(integridade) || !verificaOpcoes(canFD)) {
    Serial.println("Opcao inválida");
    unsigned char * retorno = malloc((strlen("Opcao inválida") + 1) * sizeof(unsigned char));
    strcpy(retorno, "Opcao inválida");
    return retorno;
  }

  unsigned char len = strlen(msg);
  unsigned char opcao = (canFD << 2) | (confidencialidade << 1) | (integridade << 0);
  switch (opcao) {
  case 0: //normal
    return msg;
    break;

  case 1: { //integridade
    unsigned char * hash = hashSHA256(msg, len); //8 bytes
    unsigned char * msgEhash = (unsigned char * ) malloc((16 + 1) * sizeof(unsigned char));
    for (char i = 0; i < 16; i++) {
      if (i < 8)
        msgEhash[i] = msg[i];

      else
        msgEhash[i] = hash[i - 8];
    }
    msgEhash[16] = '\0';
    return msgEhash; //16 bytes
  }
  break;

  case 2: { //confidencialidade
    unsigned char * temp = encrypt3DES(msg);
    temp[len] = '\0';
    return temp; //8 bytes
  }
  break;

  case 3: { //confidencialdade e integridade. AQUI SERÁ UTILIZADA A CIFRA DE VERNAM (o OTP). Falta implementá-lo. Enquanto isso, usaremos o 3DES!!!!
    unsigned char * tempMsg = encrypt3DES(msg); //8 bytes
    unsigned char * tempHash = hashSHA256(tempMsg, (unsigned char) strlen(tempMsg)); //8 bytes pq o retorno do 3des éh 8 bytes
    unsigned char * msgEhash = (unsigned char * ) malloc((16 + 1) * sizeof(unsigned char));
    for (char i = 0; i < 16; i++) {
      if (i < 8)
        msgEhash[i] = tempMsg[i];

      else
        msgEhash[i] = tempHash[i - 8];
    }
    msgEhash[16] = '\0';
    return msgEhash; //16 bytes
  }
  break;
  case 4: //canfd e normal
    return msg;
    break;

  case 5: { //canfd e integridade
    unsigned char * hash = hashSHA256(msg, len); // será hash_size==32 depois
    unsigned char * msgEhash = (unsigned char * ) malloc((16 + 1) * sizeof(unsigned char)); //o malloc poderia ser 40 bytes
    for (char i = 0; i < 16; i++) {
      if (i < 8)
        msgEhash[i] = msg[i];

      else
        msgEhash[i] = hash[i - 8];
    }
    msgEhash[16] = '\0';
    return msgEhash; // 40 bytes. 8 payload e 32 hash
  }
  break;

  case 6: { //canfd e confidencialidade
    unsigned char * temp = encryptAES(msg);
    temp[16] = '\0';
    return temp;
  }
  break;

  case 7: { //canfd ,confidencialdade e integridade
    unsigned char * tempMsg = encryptAES(msg); //16 bytes
    unsigned char * tempHash = hashSHA256(tempMsg, (unsigned char) strlen(tempMsg)); //16 bytes pq o retorno do aes éh 16 bytes
    unsigned char * msgEhash = (unsigned char * ) malloc((32 + 1) * sizeof(unsigned char));
    for (char i = 0; i < 32; i++) {
      if (i < 16)
        msgEhash[i] = tempMsg[i];

      else
        msgEhash[i] = tempHash[i - 16];
    }
    msgEhash[32] = '\0';
    return msgEhash;
  }

  break;

  }

}
//------------------------------------------------------------------------------------ //

//------------------------------------------ Configurando oq será utilizado: Saída seria, MCP2515 ------------------------------------------ //
void setup() {
  while (!Serial);
  Serial.begin(9600);
  (!mcp2515.reset()) ? Serial.println("reset ok!"): Serial.println("reset falhou");
  (!mcp2515.setBitrate(CAN_500KBPS, MCP_8MHZ)) ? Serial.println("bitrate ok!"): Serial.println("bitrate falhou!");
  (!mcp2515.setNormalMode()) ? Serial.println("modo definido ok"): Serial.println("modo definido falha");
  delay(1000);

}
//------------------------------------------------------------------------------------ //

void loop() {
  uint8_t i = 0;
  char texto[512] = {};

  for (uint8_t j = 0; j < 8; j++) {
    Serial.print("\nLoop na opcao: ");
    Serial.println(j);
    char * msgAdulterada = cryptoMessagesCAN(mensagemReferencia, (j & 4) >> 2, (j & 2) >> 1, (j & 1) >> 0);
    uint8_t tamMsg = (uint8_t) strlen(msgAdulterada);
    uint8_t k = 0;
    for (i = 0; i < sizeof(ids_radar) / sizeof(ids_radar[0]); i++) {
      sprintf(texto, "\nMensagem referencia:%s\nMensagem a ser enviada: ID:%x\tDLC:%d\tPayload:%s", mensagemReferencia, ids_radar[i], tamMsg, msgAdulterada);
      Serial.println(texto);
      delay(500);
      if (tamMsg < 9) {
        struct can_frame * mensagem = prepararFrame(ids_radar[i], tamMsg, msgAdulterada);
        printCANMessages(mensagem);
        mcp2515.sendMessage(mensagem);
        free(mensagem);
      } else { //mensagem maior que 8 bytes        
        for (k = 0; k < tamMsg / 8; k++) {
          if (!k) { // caso inicial
            enviarMensagemCAN(msgAdulterada, ids_radar[i], (-1));
          } else { // caso intermediario
            enviarMensagemCAN( & (msgAdulterada[8 * k]), ids_radar[i], (-1));
          }
        }
        if (k == (tamMsg / 8) && tamMsg % 8 != 0) { // caso final
          enviarMensagemCAN( & (msgAdulterada[8 * k]), ids_radar[i], (unsigned char) tamMsg % 8);
        }
      }

    }
    for (i = 0; i < sizeof(ids_cluster) / sizeof(ids_cluster[0]); i++) {

      sprintf(texto, "\nMensagem referencia:%s\nMensagem a ser enviada: ID:%x\tDLC:%d\tPayload:%s", mensagemReferencia, ids_cluster[i], tamMsg, msgAdulterada);
      Serial.println(texto);
      delay(500);
      if (tamMsg < 9) {
        struct can_frame * mensagem = prepararFrame(ids_cluster[i], tamMsg, msgAdulterada);
        printCANMessages(mensagem);
        mcp2515.sendMessage(mensagem);
        free(mensagem);
      } else { //mensagem maior que 8 bytes
        for (k = 0; k < tamMsg / 8; k++) {
          if (!k) { // caso inicial 
            enviarMensagemCAN(msgAdulterada, ids_cluster[i], (-1));
          } else { // caso intermediario
            enviarMensagemCAN( & (msgAdulterada[8 * k]), ids_cluster[i], (-1));
          }
        }
        if (k == (tamMsg / 8) && tamMsg % 8 != 0) { // caso final
          enviarMensagemCAN( & (msgAdulterada[8 * k]), ids_cluster[i], tamMsg % 8);
        }
      }

    }
    for (i = 0; i < sizeof(ids_object) / sizeof(ids_object[0]); i++) {

      sprintf(texto, "\nMensagem referencia:%s\nMensagem a ser enviada: ID:%x\tDLC:%d\tPayload:%s", mensagemReferencia, ids_object[i], tamMsg, msgAdulterada);
      Serial.println(texto);
      delay(500);
      if (tamMsg < 9) {
        struct can_frame * mensagem = prepararFrame(ids_object[i], tamMsg, msgAdulterada);
        printCANMessages(mensagem);
        mcp2515.sendMessage(mensagem);
        free(mensagem);
      } else { //mensagem maior que 8 bytes
        for (k = 0; k < tamMsg / 8; k++) {
          if (!k) { // caso inicial 
            enviarMensagemCAN(msgAdulterada, ids_object[i], (-1));
          } else { // caso intermediario
            enviarMensagemCAN( & (msgAdulterada[8 * k]), ids_object[i], (-1));
          }
        }
        if (k == (tamMsg / 8) && tamMsg % 8 != 0) { // caso final
          enviarMensagemCAN( & (msgAdulterada[8 * k]), ids_object[i], tamMsg % 8);
        }
      }

    }
  }

  delay(1500);

}
