#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

FILE *abrir_Mensaje     ( FILE *Mensaje);														// Fichero a leer

void K_Extraccion_Clave ( uint8_t *K1 , uint8_t *K2 , uint16_t contrasena);						// Función para obtener las 2 Subclaves
void M_Cifrado          ( uint8_t palabra , uint8_t *k1, uint8_t *palabra_codigo );				// Función de cifrado f(K)
void Permutacion_IP_I   ( uint8_t *palabra_codigo);												// Permutación inversa final
void Permutacion_IP     ( uint8_t palabra , uint8_t *palabra_codigo);							// Permutación inversa
void elevado			(int base , int exponente , int *puente);								// Función de ayuda a la transcripción a binario
void Sacar_contrasena 	( uint16_t cambio , uint16_t *contrasena);								// Función para pasar a binario las dos segundas claves ( En el caso de querer triple encriptación ) 

int main ( int argc , int *argv[]){
	
	char entrada,salida;
	
	FILE *Mensaje;																				// Fichero a leer
	FILE *Codigo;																				// Fichero en el que escribimos
	
	
	uint16_t permutacion10 , contrasena ,mascara;
	
	uint8_t K1 ;
	uint8_t K2 ;
	uint8_t palabra ,prueba;
	uint8_t palabra_codigo ;
	
	int metodo,puente,puente2,puente3,i,j,base,exponente;										 
	int encriptacion, *decision,cambio,algoritmo,decena;											
	int klaves[2];																				// Vector para almacenar las dos claves en caso de que se quiera triple encriptación
	
	char *texto_entrada , *texto_salida , *opcion;
	
	char representacion[9];
	
	int o;
   const char * optstring = "m:e:k:"; // Hay tres opciones -abc, en las que hay dos puntos después de la opción c, por lo que debe haber parámetros detrás
    									// En caso de dejar alguno de los parametros vacíos ´remitirá una error en la terminal y no ejecutará el algoritmo
   algoritmo=0; 
   while ((o = getopt(argc, argv, optstring)) != -1) {
   	switch (o) {
      	case 'm':													// Método a aplicar 
      		sscanf(optarg,"%d",&decision);
      	
      		if(decision != 1 && decision != 0) {
	   		printf(" Metodo de resolucion no conocido \n");
      		}
      		
      	case 'e':												 	// Entrada de ficheros
      		texto_entrada = (char *) argv[4];
				texto_salida  = (char *) argv[5];
      		break;
      	case 'k':													// Claves a utilizar
      		sscanf(argv[7],"%d",&cambio);
      		break;
      	case 'h':													// Explicación como utilizar el programa
      		printf(" -m --> Metodo de ejecucio: ( 0 ) --> Encriptacion   ( 1 ) --> Desencriptacion \n");
      		printf(" -e --> Entrada de ficheros 1 fichero a encriptar/desencriptar  2 fichero en el que guardar la operacion\n");
      		printf(" -k --> Clave para entriptar/Desencriptar, en caso de poner 3 claves hará la triple encriptacion \n");
      		break;
      	case '?':													// Fallo en la introducción de los argumentos
      		printf("error optopt: %c\n", optopt);
      		printf("error opterr: %d\n", opterr);
      	break;
      }
	}	
	
	// Los argumentos entran en main() en forma de cadena de caracteres, tenemos que transformarlo en lo que queremos, un entero en este caso	


	Mensaje = fopen(texto_entrada,"rb");							// Fichero de lectura permiso de lectura bin
	Codigo	= fopen(texto_salida,"wb+");							// Fichero final , permiso de escritura bin , en caso de no existir lo crea 
	
	
	contrasena = 0x00;
	mascara = contrasena;
	puente = 1;
	decena = 10;
	if(argv[8]!=NULL){												// Tenemos 3 claves , triple encriptación
      //printf("Aplicamos el triple Encriptado\n");
		algoritmo = 1;												// Si solo entra una contraseña es que estamos en SDES normal
		sscanf(argv[8],"%d",&klaves[0]);
		sscanf(argv[9],"%d",&klaves[1]);
	}
	for( i = 9 ; i >=0 ; i-- ){
		elevado ( decena , i , &puente);							// No utilizo la función POW porque da problemas en linux
		mascara = 1 << i;
		if( (cambio - puente) >= 0 ){
			cambio -= puente;
			contrasena += mascara;									// Contraseña obtenida 
		}
	}

	if(Mensaje == NULL){											// Archivo de lectura no encontrado 
		printf("Archivo no leido");
	}
	else{

		K_Extraccion_Clave ( &K1 , &K2 , contrasena );				// Obtención de las subclaves
		puente2 = K1;
		puente3 = K2;
		
		if( decision == 1){											// inversión del orden de las subclaves para desencriptacion
			//Encriptamos Archivo
			K1 = puente3;
			K2 = puente2;
		}
		
		fscanf (Mensaje,"%c",&palabra);								// Leemos el fichero
		
		while ( !feof ( Mensaje )  ){										// Todavía no he actualizado la funcion M_cifrado						
			
		//	printf("Palabra Mensaje leida de fichero: 0x%02X == %c \n",palabra,palabra);
		//	printf("Clave Sub 1: 0x%02X \n",(K1));
		//	printf("Clave Sub 2: 0x%02X \n",(K2));
		//	printf("Metodo %i           \n",(decision));
			
			Permutacion_IP      ( palabra , &palabra_codigo );				// Permutación inicial 
			
			palabra = palabra_codigo;										// La palabra a codificar es el resultado de la Permutacio IP
			
			M_Cifrado ( palabra , &K1 , &palabra_codigo );					// Llamamos a al función que 
			
			palabra = palabra_codigo;										// Introducimos el resultado obtenido con la primera iteracion del mensaje y la clave K1
			
			K1 = K2;														// Ahora usaremos la clave K sub 2
			
			M_Cifrado ( palabra , &K1 , &palabra_codigo );					// Obtenemos el resultado pero faltar invertir el SW final y realizar la permuatacio Inversa del Código Permutacion IP^-1
			
			Permutacion_IP_I ( &palabra_codigo);							// Obtenemos la palabra código final
			
			if(algoritmo == 1){												// En caso de que sea triple encriptación repetimos el mismo procedimientos dos veces más
				for(j=0;j<=1;j++){
					cambio = klaves[i];
					Sacar_contrasena ( cambio , &contrasena);	
				
					K_Extraccion_Clave ( &K1 , &K2 , contrasena );
					puente2 = K1;
					puente3 = K2;
				
					if( decision == 1){
						K1 = puente3;
						K2 = puente2;
					}
					palabra = palabra_codigo;
					Permutacion_IP      ( palabra , &palabra_codigo );
					palabra = palabra_codigo;
					M_Cifrado ( palabra , &K1 , &palabra_codigo );
					palabra = palabra_codigo;
					K1 = K2;
					M_Cifrado ( palabra , &K1 , &palabra_codigo );
					Permutacion_IP_I ( &palabra_codigo);
					K1 = puente2;
					K2 = puente3 ;
					if( decision == 1){
						K1 = puente3;
						K2 = puente2;
					}
				}
			}
			
			fprintf(Codigo,"%c",palabra_codigo);							// 
			
			K1 = puente2;
			K2 = puente3 ;
			if( decision == 1){
				K1 = puente3;
				K2 = puente2;
			}
			fscanf (Mensaje,"%c",&palabra);
		}
		
	}
}

	/********************************************************/
	//      Obtenemos claves de cifrado K1 Y K2              /
	/********************************************************/

void K_Extraccion_Clave ( uint8_t *K1 , uint8_t *K2 , uint16_t contrasena){
	
	int matriz[10]={ 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };							//Matriz = Orden en el que tengo que cambiar los factores
	int matriz2[8]={6,3,7,4,8,5,10,9};
	int i,desplazamiento,valor;
	uint16_t clave,puente,mascara,permutacion10,permutacion10_2,permutacion10_3;
	uint8_t palabra , R0,L0;
	
	clave = contrasena;
	//printf("Clave leida: 0x%04X \n",clave);
	permutacion10 = 0x0000;
	matriz[0]=3;
	matriz2[0]=6;
	
	
	for ( i = 0 ; i < 10 ; i++){
		
		desplazamiento = matriz[i];												//Obtengo el numero de desplazamientos para saber como está el bit [ 1 ó 0]
		puente = clave;	
		desplazamiento = 10 - desplazamiento; 
		valor = (puente >> ( desplazamiento ) ) & 0x01;							//averiguo el valor del bit en esa posición		
		if(valor == 0x01){														//Detecto que ha entrado un 1
			puente = clave;
			mascara = 1 << (10 - (i+1) );
			permutacion10 = permutacion10 | mascara;
		}
		mascara = 0x0000;
	}
	//printf("Clave Permutada: 0x%04X \n",permutacion10);

	/******************************************************************/
	//     Segunda parte de la Clave  ==> Permutaciones  LS-1 & LS-2   /
	/******************************************************************/ 
	
	uint16_t r0, l0,r1,l1,r2,l2,mascarar0,mascaral0,permutacion10_21,permutacion10_4;
	
	mascarar0 = 0x001F;
	mascaral0 = 0x03E0;
	r0 = permutacion10 & mascarar0;
	l0 = permutacion10 & mascaral0;
	
	puente = r0 & 0x0010;										// Obtenemos el valor del bit 5
	
	r0 = r0 << 1;
	r0 = r0 & mascarar0;
	if (puente == 0x0010){
		r1 = r0 | 0x0001;
	}
	else{
		r1 = r0;
	}
	
	puente = l0 & 0x0200;										//Obtenemos el valor del bit 10
	l0 = l0 << 1;
	l0 = l0 & mascaral0;
	if (puente == 0x0200){
		l1 = l0 | 0x0020;
	}
	else{
		l1 = l0;
	}
	permutacion10_2 = r1 | l1;									// Clave preparada para ser reducida
	//printf("Clave Dividida 1: 0x%04X \n",permutacion10_2);

	r2 = r1;													// Para obtener la segunda sub clave tengo que hacer un doble LS-2 a r1 y l1
	l2 = l1;
	r1 = ( r1 & 0x0018 ) >> 3;									// Me quedo con los dos primeros valores de l1 y r1
	l1 = ( l1 & 0x0300 ) >> 3;
	r2 = ( r2 << 2 ) | r1 ;										// desplazo y sumo los dos primeros valores en el último lugar
	l2 = ( l2 << 2 ) | l1 ;
	r2 = r2 & mascarar0;										// Hago la mascara para que el desplazamiento sea circular 
	l2 = l2 & mascaral0;
 	
 	permutacion10_21 = r2 | l2;									// Clave preparada para ser reducida
	//printf("Clave Dividida 2: 0x%04X \n",permutacion10_21);

	/********************************************************/
	//      Tercera parte de la Clave  ==> Reducir           /
	/********************************************************/ 

	mascara = 0x0000;
	permutacion10_3 = 0x0000;
	for ( i = 0 ; i < 8 ; i++){
		desplazamiento = matriz2[i];												//Obtengo el numero de desplazamientos para saber como está el bit [ 1 ó 0]
		puente = permutacion10_2;	
		desplazamiento = 10 - desplazamiento; 
		valor = (puente >> (desplazamiento ) ) & 0x0001;								//averiguo el valor del bit en esa posición		
		
		if(valor == 0x0001){																//Detecto que ha entrado un 1
			puente = permutacion10_2;
			mascara = 1 << (8 - (i+1) );
			permutacion10_3 = permutacion10_3 | mascara;
		}
		mascara = 0x0000;
	}
	*K1 = permutacion10_3;
	//printf("[==> Clave Sub 1: 0x%02X <== ] \n",(*K1));
	  
	/* **** Reduccion para obtener la segunda sub clave   ****** */
	  
	mascara = 0x0000;
	permutacion10_4 = 0x0000;
	for ( i = 0 ; i < 8 ; i++){
		desplazamiento = matriz2[i];												//Obtengo el numero de desplazamientos para saber como está el bit [ 1 ó 0]
		puente = permutacion10_21;	
		desplazamiento = 10 - desplazamiento; 
		valor = (puente >> (desplazamiento ) ) & 0x0001;								//averiguo el valor del bit en esa posición		
		if(valor == 0x0001){															//Detecto que ha entrado un 1
			puente = permutacion10_21;
			mascara = 1 << (8 - (i+1) );
			permutacion10_4 = permutacion10_4 | mascara;
		}
		mascara = 0x0000;
	}
	*K2 = permutacion10_4;
	//printf("[==> Clave Sub 2: 0x%02X <== ] \n",(*K2));
		
}
	
	 
	/********************************************************/
	//      Cifrado  ==> Ciframos Mensaje ( 2 iteraciones )  /
	/********************************************************/
	
void M_Cifrado ( uint8_t palabra , uint8_t *K1 , uint8_t *palabra_codigo){
	
	
	int matriz4[8]={4,1,2,3,2,3,4,1};
	int i,desplazamiento , valor,filas,columnas;
	int S1[4][4]={0,1,2,3,
	              2,0,1,3,
				  3,0,1,0,
				  2,1,0,3};
				  
	int S0[4][4]={1,0,3,2,
	              3,2,1,0,
				  0,2,1,3,
				  3,1,3,2};
				  
	int matriz5[4]={2,4,3,1};
	
	matriz4[0]=4;
	matriz5[0]=2;
	
	uint8_t  permutacionM1 , puente , mascara , R0 , L0 , R0EP, FK1R0, R1,L1,R2,L2,permutacion4;
	

	
	permutacionM1 = palabra;
	
	R0 = permutacionM1 & 0x0F;													//	E/P
	L0 = permutacionM1 & 0xF0;													//	Reservo para la ultima suma 
	
	//printf("L0: 0x%02X  R0: 0x%02X \n",L0,R0);
	
	R0EP = 0x00;
	for ( i = 0 ; i < 8 ; i++){
		desplazamiento = matriz4[i];												//Obtengo el numero de desplazamientos para saber como está el bit [ 1 ó 0]
		puente = R0;	
		desplazamiento = 4 - desplazamiento; 
		valor = (puente >> (desplazamiento ) ) & 0x01;								//averiguo el valor del bit en esa posición		
		if(valor == 0x0001){															//Detecto que ha entrado un 1
			puente = R0;
			mascara = 1 << (8 - (i+1) );
			R0EP = R0EP | mascara;
		}
		mascara = 0x0000;
	}	
	//printf("Mensaje Expandido: 0x%02X \n",R0EP);							// Expandimos los últimos 4 bits de R0
	
	FK1R0 = R0EP ^ (*K1); 														// Operación XOR entre R0 expandido y subclave 1
	//printf("Salida Funcion F(k1 ^R0): 0x%02X \n",FK1R0);
	
	
	/* ******************* Cajas S ********************** */
	
	
	
	R1 = FK1R0 & 0x0F;
	L1 = FK1R0 & 0xF0;
	
	/* Caja S1 */
	
	uint8_t f1,f2,c1,c2,s1,s0;
	
	//printf("R1: 0x%02X \n",R1);
	//printf("L0: 0x%02X \n",L1);
	f1= (R1 >> 3) & 0x01;
	c1= (R1 >> 2) & 0x01;
	f2= R1 & 0x01;
	c2 = (R1 >> 1) & 0x01;
	f1 = ( f1 << 1) | f2;
	c1 = ( c1 << 1) | c2;
	filas = f1;
	columnas = c1;
	//printf("Filas S1: 0x%02X    Columnas S1: 0x%02X \n",f1,c1);
	//printf("Filas S1 %i         Columnas S1: %i\n",filas,columnas);
	s1 = S1[filas][columnas];
	//printf("Salida Puerta S1 0x%02X \n",s1);
	
	
	f1= (L1 >> 7) & 0x01;
	f2= (L1 >> 4) & 0x01;
	c1= (L1 >> 6) & 0x01;
	c2 =(L1 >> 5) & 0x01;
	f1 = ( f1 << 1) | f2;
	c1 = ( c1 << 1) | c2;
	filas = f1;
	columnas = c1;
	//printf("Filas S0: 0x%02X    Columnas S0: 0x%02X \n",f1,c1);
	//printf("Filas S0 %i        Columnas %i\n",filas,columnas);
	s0 = S0[filas][columnas];

	//printf("Salida S0: 0x%02X    Salida S1: 0x%02X \n",s0,s1);
	s1 = (s0 << 2) | s1;
	//printf("Salida Puertas 0x%02X \n",s1);
	
	
	
	permutacion4=0X00;																
	for ( i = 0 ; i < 4 ; i++){
		desplazamiento = matriz5[i];												//Obtengo el numero de desplazamientos para saber como está el bit [ 1 ó 0]
		puente = s1;	
		desplazamiento = 4 - desplazamiento; 
		valor = (puente >> (desplazamiento ) ) & 0x0001;								//averiguo el valor del bit en esa posición		
		if(valor == 0x01){															//Detecto que ha entrado un 1
			puente = s1;
			mascara = 1 << (4 - (i+1) );
			permutacion4 = permutacion4 | mascara;
		}
		mascara = 0x0000;
	}
	// R0 L0 
	//printf("Salida Permutacion 4: 0x%02X \n",permutacion4);
	L0 = L0 >> 4;
	L1 = L0 ^ permutacion4;

	//printf("Salida F(P4 ^ L0 ) 4: 0x%02X \n",L1);
	
	puente = L1;																// SW invertimos orden del mensaje 
	L1 = R0;
	R1 = puente;
	
	//printf("L1: 0x%02X    r1: 0x%02X \n",L1,R1);								// Mensaje preparado para volver a entrar al Deco [SW]
	L1 = L1 << 4;
	puente = L1 | R1;
	//printf("Salida SW: 0x%02X \n",puente);
	
	*palabra_codigo = puente;
}

	/********************************************************/
	//      Preparamos Mensaje para ser cifrado              /
	/********************************************************/

void Permutacion_IP     ( uint8_t palabra , uint8_t *palabra_codigo){
	
	int matriz3[8]={2,6,3,1,4,8,5,7};
	uint8_t permuacionM10,mascara,puente,permutacionM1;
	int desplazamiento, i, valor;
	matriz3[0]=2;
	
	permutacionM1 = 0x00;
	
	for ( i = 0 ; i < 8 ; i++){
	desplazamiento = matriz3[i];												//Obtengo el numero de desplazamientos para saber como está el bit [ 1 ó 0]
	puente = palabra;	
	desplazamiento = 8 - desplazamiento; 
	valor = (puente >> (desplazamiento ) ) & 0x0001;								//averiguo el valor del bit en esa posición		
	if(valor == 0x0001){															//Detecto que ha entrado un 1
		puente = palabra;
		mascara = 1 << (8 - (i+1) );
		permutacionM1 = permutacionM1 | mascara;
	}
	mascara = 0x0000;
	}
	
	*palabra_codigo = permutacionM1;
	//printf("Permutacio IP 1 Mensaje: 0x%02X \n",permutacionM1);
}
	
	/********************************************************/
	//      Preparamos mensaje cifrado para ser escrito      /
	/********************************************************/
	
void Permutacion_IP_I   ( uint8_t *palabra_codigo){
	
	int i,desplazamiento,valor;
	int matriz[8]={4,1,3,5,7,2,8,6};
	
	uint8_t r0 , l0 , puente,mascara1,mascara2,final,mascara;
	
	matriz[0]=4;
	mascara1 = 0x0F;
	mascara2 = 0xF0;
	r0 = (*palabra_codigo) & mascara1;
	l0 = (*palabra_codigo) & mascara2;
	r0 = r0 << 4 ;
	l0 = l0 >> 4 ;
	
	r0 = r0 | l0 ; 
	
	//printf("Codigo que entra en la Permutacion IP^-1: 0x%02X \n",r0);
	
	final = 0x00;
	mascara = 0x00;
	for ( i = 0 ; i < 8 ; i++){
		desplazamiento = matriz[i];												//Obtengo el numero de desplazamientos para saber como está el bit [ 1 ó 0]
		puente = r0;	
		desplazamiento = 8 - desplazamiento; 
		valor = (puente >> (desplazamiento ) ) & 0x0001;								//averiguo el valor del bit en esa posición		
		if(valor == 0x0001){															//Detecto que ha entrado un 1
			puente = r0;
			mascara = 1 << (8 - (i+1) );
			final = final | mascara;
		}
		mascara = 0x0000;
	}
	
	//printf("Codigo SALIDA en la Permutacion IP^-1: 0x%02X \n",final);
	
	*palabra_codigo = final;	
}

void elevado ( int decena, int exponente , int *puente){
	int i,resultado;
	resultado = decena;
	for ( i = 1; i < exponente ; i ++){
		resultado = resultado * decena;
	}
	(*puente) = resultado;
}	
void Sacar_contrasena ( uint16_t cambio , uint16_t *contrasena){
	 int i,decena = 10, puente = 1;
	 uint16_t mascara;
	for( i = 9 ; i >=0 ; i-- ){
		elevado ( decena , i , &puente);
		mascara = 1 << i;
		if( (cambio - puente) >= 0 ){
			cambio -= puente;
			(*contrasena) += mascara;
		}
	}
}
