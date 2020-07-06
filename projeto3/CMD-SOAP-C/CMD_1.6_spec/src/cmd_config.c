/**
 * @file cmd_config.c (C)
 * @brief Ficheiro de configuração do URL do WSDL a utilizar e da APPLICATION_ID fornecida pela AMA.
 * 
 * Copyright (c) 2020 Tempus, Lda.
 * Developed by Ricardo Pereira and Tiago Ramires - a73577@alunos.uminho.pt and pg41101@alunos.uminho.pt
 * 
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * 
 */

#include "headers/cmd_config.h"

/* ApplicationId da entidade, fornecida pela AMA */
static const char* APPLICATION_ID = "b826359c-06f8-425e-8ec3-50a97a418916";

const char* get_appid(){
	return APPLICATION_ID;
}