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
        return self.field + other

    def __radd__(self, other):
        return other + self.field

    def _check_field(self):
        return isinstance(self.field, str)

    @property
    def valid(self):
        if self.field is None:
            return not self.required
        if not self.field:
            return self.nullable
        return self._check_field()


class ArgumentsField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        return isinstance(self.field, dict)


class EmailField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, str):
            return bool(re.match("^[^@\\s]+@[a-z0-9\\-\\.]+$", self.field, re.IGNORECASE))


class PhoneField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, int):
            self.field = str(self.field)
        if isinstance(self.field, str):
            return bool(re.match("^7\\d{10}$", self.field))


class DateField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, str):
            return bool(re.match("^\\d{2}\\.\\d{2}\\.\\d{4}$", self.field))


class BirthDayField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, str):
            if re.match("^\\d{2}\\.\\d{2}\\.\\d{4}$", self.field):
                age = datetime.datetime.now() - datetime.datetime.strptime(self.field, '%d.%m.%Y')
                return (age.days // 365) <= 70


class GenderField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        return self.field in (0, 1, 2)


class ClientIDsField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _check_field(self):
        if isinstance(self.field, list):
            for i in self.field:
                if not isinstance(i, int):
                    return False
            return True


class ClientsInterestsRequest:
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)

    fields = {
        'client_ids': client_ids,
        'date': date,
    }

    def __init__(self, request_body, store):
        self.request_body = request_body
        self.store = store

        for key, value in request_body.arguments.field.items():
            if key in self.fields:
                self.fields[key].field = value

    def get_score(self):
        return scoring.get_interests(
            store=self.store,
            cid=self.client_ids.field,
        )

    @property
    def valid(self):
        return self.client_ids.valid and self.date.valid


class OnlineScoreRequest:
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

    def __init__(self, request_body, store):
        self.request_body = request_body
        self.store = store

        for key, value in request_body.arguments.field.items():
            if key in self.fields:
                self.fields[key].field = value

    def get_score(self):
        if self.request_body.is_admin:
            return 42
        return scoring.get_score(
            store=self.store,
            phone=self.phone.field,
            email=self.email.field,
            birthday=self.birthday.field,
            gender=self.gender.field,
            first_name=self.first_name.field,
            last_name=self.last_name.field,
        )

    @property
    def valid(self):
        return ((
                    self.first_name.valid and
                    self.last_name.valid and
                    self.email.valid and
                    self.phone.valid and
                    self.birthday.valid and
                    self.gender.valid
                ) and
                (
                    (self.email.field and self.phone.field) or
                    (self.first_name.field and self.last_name.field) or
                    (self.gender.field and self.birthday.field)
                ))


class MethodRequest:
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

    def __init__(self, request):
        for key, value in request.items():
            if key in self.fields:
                self.fields[key].field = value

    @property
    def valid(self):
        return (self.account.valid
                and self.login.valid
                and self.token.valid
                and self.method.valid
                and self.arguments.valid)

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
    method = None
    request_body = MethodRequest(request['body'])
    auth = check_auth(request_body)

    if auth:
        if request_body.valid:
            if request_body.method == 'online_score':
                method = OnlineScoreRequest(request_body, store)
            elif request_body.method == 'clients_interests':
                method = ClientsInterestsRequest(request_body, store)
            else:
                code = INVALID_REQUEST
        else:
            code = INVALID_REQUEST
    else:
        code = FORBIDDEN

    if method:
        if method.valid:
            response = method.get_score()
            code = OK
        else:
            code = INVALID_REQUEST

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
