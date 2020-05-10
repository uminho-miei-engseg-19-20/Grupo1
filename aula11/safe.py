#Programa em Python para o trabalho prático 11
import re, string

while True :
	#inserção do valor pelo utilizador
	valor = input("\nInsira valor a pagar (no formato xx(...)xx.xx): ")
	#verificação do valor inserido
	if not re.match("[0-9]{2,20}(\.[0-9][0-9])?$", valor) : 
		print("Inseriu um valor errado!")
	else :
		break;


while True :
	#inserção da data pelo utilizador
	data = input("\nInsira a data de nascimento (no formato DD-MM-AAAA): ")
	#verificação da data inserida
	if not re.match("(0[1-9]|(1|2)[0-9]|3[0-1])\-(0[1-9]|1[0-2])\-(19[0-9]{2}|20[0-1][0-9])$", data) : 
		print("Inseriu uma data errada!")
	else :
		break;


while True :
	#inserção do nome utilizador
	nome = input("\nInsira o nome (apenas carateres do alfabeto): ")
	#verificação do valor inserido
	if not re.match("[a-z]{3,15}( [a-z]{3,15}){0,7}$", nome) : 
		print("Inseriu um nome errado!")
	else :
		break;


while True :
	#inserção do NIF pelo utilizador
	nif = input("\nInsira o NIF (no formato xxxxxxxxx): ")
	#verificação do NIF inserido
	if not re.match("[0-9]{9}$", nif) : 
		print("Inseriu um NIF errado!")
	else :
		break;


while True :
	#inserção do NIC pelo utilizador
	nic = input("\nInsira o NIC (com 8,9 ou 10 algarismos): ")
	#verificação do NIC inserido
	if not re.match("[0-9]{8,10}$", nic) : 
		print("Inseriu um NIC errado!")
	else :
		break;


while True :
	#inserção do cc pelo utilizador
	cc = input("\nInsira o nº de cartão de crédito (no formato xxxxxxxxxxxxxxxx): ")
	#verificação do cc inserido
	if not re.match("[0-9]{16}$", cc) : 
		print("Inseriu um nº de cartão de crédito errado!")
	else :
		break;

while True :
	#inserção do cvc pelo utilizador
	cvc = input("\nInsira o CVC/CVV (no formato xxx): ")
	#verificação do cvc inserido
	if not re.match("[0-9]{3}$", cvc) : 
		print("Inseriu um CVC/CVV errado!")
	else :
		break;


while True :
	#inserção da validade pelo utilizador
	validade = input("\nInsira a validade do cartão (no formato DD/MM): ")
	#verificação da validade inserida
	if not re.match("(0[1-9]|(1|2)[0-9]|3[0-1])\/(0[1-9]|1[0-2])$", validade) : 
		print("Inseriu uma validade errada!")
	else :
		break;








