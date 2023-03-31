#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import re
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class CharField:
    def __init__(self, required, nullable):
        self.required = required
        self.nullable = nullable
        self.field = None

    def __eq__(self, other):
        return self.field == other

    def __add__(self, other):
        f = self.field if self.field else ''
        o = other if other else ''
        return f + o

    def __radd__(self, other):
        f = self.field if self.field else ''
        o = other if other else ''
        return o + f

    def _check_field(self):
        valid = isinstance(self.field, str)
        msg = 'must be string' if not valid else ''
        return valid, msg

    def validation(self):
        if self.field is None:
            valid = not self.required
            msg = 'is required but absent' if not valid else ''
        elif not self.field:
            valid = self.nullable
            msg = 'must be not empty' if not valid else ''
        else:
            valid, msg = self._check_field()
        return valid, msg

    @property
    def is_available(self):
        return bool(self.field)


class ArgumentsField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        valid = isinstance(self.field, dict)
        msg = 'must be dictionary' if not valid else ''
        return valid, msg


class EmailField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, str):
            valid = bool(re.match("^[^@\\s]+@[a-z0-9\\-\\.]+$", self.field, re.IGNORECASE))
            msg = 'must be name@domain' if not valid else ''
        else:
            valid = False
            msg = 'must be string'
        return valid, msg


class PhoneField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, int):
            self.field = str(self.field)
        if isinstance(self.field, str):
            valid = bool(re.match("^7\\d{10}$", self.field))
            msg = 'must contains 11 numbers and start with 7' if not valid else ''
        else:
            valid = False
            msg = 'must be string or integer'
        return valid, msg


class DateField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, str):
            valid = bool(re.match("^\\d{2}\\.\\d{2}\\.\\d{4}$", self.field))
            msg = 'must be set in format XX.XX.XXXX' if not valid else ''
        else:
            valid = False
            msg = 'must be string'
        return valid, msg


class BirthDayField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, str):
            valid = re.match("^\\d{2}\\.\\d{2}\\.\\d{4}$", self.field)
            if valid:
                age = datetime.datetime.now() - datetime.datetime.strptime(self.field, '%d.%m.%Y')
                valid = (age.days // 365) <= 70
                msg = 'age must be less than 70 years old' if not valid else ''
            else:
                msg = 'must be set in format XX.XX.XXXX'
        else:
            valid = False
            msg = 'must be string'
        return valid, msg


class GenderField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, int):
            valid = self.field in (0, 1, 2)
            msg = 'must be in (0, 1, 2)' if not valid else ''
        else:
            valid = False
            msg = 'must be integer'
        return valid, msg

    def validation(self):
        if self.field is None:
            valid = not self.required
            msg = 'is required but absent' if not valid else ''
        elif self.field or self.field == 0:
            valid, msg = self._check_field()
        else:
            valid = self.nullable
            msg = 'must be not empty' if not valid else ''

        return valid, msg

    @property
    def is_available(self):
        return bool(self.field) or self.field == 0


class ClientIDsField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, list):
            valid = True
            for i in self.field:
                valid = valid and isinstance(i, int)
            msg = 'must contains only integers' if valid else ''
        else:
            valid = False
            msg = 'must be list'
        return valid, msg


class GetRequestFields:
    fields = {}
    
    def __init__(self, data, context, store):
        for key, value in self.fields.items():
            value.field = data[key] if key in data else None

        self.data = data
        self.context = context
        self.store = store
        self.valid, self.response, self.code = True, '', None

    def validation(self):
        for field_name, field in self.fields.items():
            v, m = field.validation()
            self.valid = self.valid and v
            self.response = f'{self.response}{field_name} not valid: {m}; ' if not v else self.response


class ClientsInterestsRequest(GetRequestFields):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)

    fields = {
        'client_ids': client_ids,
        'date': date,
    }

    def __init__(self, request_data, context, store):
        super().__init__(request_data, context, store)
        self.validation()

    def get_score(self):
        if not self.valid:
            return self.response, INVALID_REQUEST

        self.context['nclients'] = len(self.client_ids.field)

        self.response = {}
        for _id in self.client_ids.field:
            self.response[_id] = scoring.get_interests(store=self.store, cid=self.client_ids.field)

        return self.response, OK


class OnlineScoreRequest(GetRequestFields):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    fields = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'phone': phone,
        'birthday': birthday,
        'gender': gender,
    }
    pairs = (('first_name', 'last_name'), ('email', 'phone'), ('birthday', 'gender'))

    def __init__(self, request_data, context, store, admin=False):
        super().__init__(request_data, context, store)
        self.admin = admin
        self.validation()
        self.pairs_validation()

    def pairs_validation(self):
        pair_valid = False
        msg = 'must be one pair of first_name-last_name, email-phone, birthday-gender'
        for pair in self.pairs:
            v = True
            for f in pair:
                v = v and self.fields[f].is_available
            pair_valid = pair_valid or v
        self.response = f'{self.response} {msg}' if not pair_valid else self.response
        self.valid = self.valid and pair_valid

    def get_score(self):
        self.context['has'] = list(self.data.keys())

        if not self.valid:
            return self.response, INVALID_REQUEST

        if self.admin:
            self.response = {"score": 42}
        else:
            score = scoring.get_score(
                store=self.store,
                phone=self.phone.field,
                email=self.email.field,
                birthday=self.birthday.field,
                gender=self.gender.field,
                first_name=self.first_name.field,
                last_name=self.last_name.field,
            )
            self.response = {"score": score}

        return self.response, OK


class MethodRequest(GetRequestFields):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    fields = {
        'account': account,
        'login': login,
        'token': token,
        'arguments': arguments,
        'method': method
    }

    def __init__(self, request_body, context, store):
        super().__init__(request_body, context, store)
        self.get_score_method = None
        self.validation()

    def get_score(self):
        if not self.valid:
            return self.response, INVALID_REQUEST

        if self.method.field == 'online_score':
            self.get_score_method = OnlineScoreRequest(
                self.arguments.field, self.context, self.store, self.is_admin)
        elif self.method.field == 'clients_interests':
            self.get_score_method = ClientsInterestsRequest(
                self.arguments.field, self.context, self.store)
        else:
            self.response = 'invalid request method'
            return self.response, INVALID_REQUEST

        self.response, self.code = self.get_score_method.get_score()
        return self.response, self.code

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()
        ).hexdigest()
    else:
        digest = hashlib.sha512(
            (request.account + request.login + SALT).encode()
        ).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    response, code = None, None
    method_request = MethodRequest(request['body'], ctx, store)

    if not method_request.valid:
        code = INVALID_REQUEST
        return method_request.response, code

    auth = check_auth(method_request)

    if not auth:
        code = FORBIDDEN
        return ERRORS[code], code

    response, code = method_request.get_score()

    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        data_string = ''
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode())
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
