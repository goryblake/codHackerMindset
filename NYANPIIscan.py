# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener

def validate_cpf(cpf):
    if cpf == cpf[0] * 11:
        return False
    sum_ = sum(int(cpf[i]) * (10 - i) for i in range(9))
    digit1 = 11 - (sum_ % 11)
    digit1 = 0 if digit1 >= 10 else digit1
    sum_ = sum(int(cpf[i]) * (11 - i) for i in range(10))
    digit2 = 11 - (sum_ % 11)
    digit2 = 0 if digit2 >= 10 else digit2
    return cpf[-2:] == "{}{}".format(digit1, digit2)

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("PII Scanner")
        callbacks.registerHttpListener(self)
        print("NYAN PIIScanner2, Installation OK!!! :3")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            # Extraindo as informações da resposta (response)
            request_info = self._helpers.analyzeRequest(messageInfo)
            body = messageInfo.getResponse()[request_info.getBodyOffset():]
            body_str = self._helpers.bytesToString(body)

            # Capturando qualquer CVC de 3 dígitos do h2
            cvc_pattern = re.compile(r'<h2[^>]*>(.*?)<\/h2>', re.IGNORECASE)
            h2_matches = cvc_pattern.findall(body_str)

            cvc_value = None

            # Extraindo qualquer número de 3 dígitos que não seja CVC
            for match in h2_matches:
                digits = re.findall(r'\b\d{3}\b', match)
                if digits:
                    cvc_value = digits[0]  # Captura o primeiro CVC encontrado
                    break

            # Padrão para números de telefone: +55 (XX) XXXXX-XXXX
            phone_pattern = re.compile(r'\+55 \(\d{2}\) \d{5}-\d{4}')
            phone_matches = phone_pattern.findall(body_str)

            # Extraindo CPF
            cpf_pattern = re.compile(r'\b\d{11}\b')
            possible_cpf = cpf_pattern.findall(body_str)
            possible_cpf = list(set(possible_cpf))  # Remove duplicatas
            cpf_ok = [cpf for cpf in possible_cpf if validate_cpf(cpf)]

            # Padrão para números de cartão de crédito
            cc_pattern = re.compile(r'\b\d{4} \d{4} \d{4} \d{4}\b')
            cc_matches = cc_pattern.findall(body_str)

            # Padrão para CNPJ: 12.345.678/0001-00
            cnpj_pattern = re.compile(r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b')
            cnpj_matches = cnpj_pattern.findall(body_str)

            # Padrão para RG: 417245683 (apenas números)
            rg_pattern = re.compile(r'\b\d{7,9}\b')
            rg_matches = rg_pattern.findall(body_str)

            # Exibe apenas as informações válidas
            if cvc_value:
                print("CVC: %s" % cvc_value)
            if phone_matches:
                for phone in phone_matches:
                    print("Cell phone number: %s" % phone)
            if cpf_ok:
                print("CPF: %s" % cpf_ok[0])
            if cc_matches:
                for cc in cc_matches:
                    print("Credit Card Number: %s" % cc)
            if cnpj_matches:
                for cnpj in cnpj_matches:
                    print("CNPJ: %s" % cnpj)
            if rg_matches:
                for rg in rg_matches:
                    print("RG: %s" % rg)
