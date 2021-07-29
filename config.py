#!/usr/bin/env python
# -*- coding: UTF-8 -*-
class global_var:
    getpriv = False
    newUser = ""
    targetName = ""
    newPassword = ""
    ccache = ""
    dcsync = False
    pki = False
    lock = False

def set_lock(status):
    global_var.lock = status
def get_lock():
    return global_var.lock


def set_pki(status):
    global_var.pki = status
def get_pki():
    return global_var.pki


def set_dcsync(status):
    global_var.dcsync = status
def get_dcsync():
    return global_var.dcsync

def set_priv(status):
    global_var.getpriv = status
def get_priv():
    return global_var.getpriv


def set_newUser(value):
    global_var.newUser = value
def get_newUser():
    return global_var.newUser


def set_targetName(value):
    global_var.targetName = value
def get_targetName():
    return global_var.targetName


def set_newPassword(value):
    global_var.newPassword = value
def get_newPassword():
    return global_var.newPassword


def set_ccache(value):
    global_var.ccache = value


def get_ccache():
    return global_var.ccache

