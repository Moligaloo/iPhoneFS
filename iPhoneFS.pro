#-------------------------------------------------
#
# Project created by QtCreator 2013-04-27T16:08:26
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = iPhoneFS
TEMPLATE = app
INCLUDEPATH += Include
SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h \
    Include/libimobiledevice/screenshotr.h \
    Include/libimobiledevice/sbservices.h \
    Include/libimobiledevice/restore.h \
    Include/libimobiledevice/notification_proxy.h \
    Include/libimobiledevice/mobilesync.h \
    Include/libimobiledevice/mobilebackup2.h \
    Include/libimobiledevice/mobilebackup.h \
    Include/libimobiledevice/mobile_image_mounter.h \
    Include/libimobiledevice/lockdown.h \
    Include/libimobiledevice/libimobiledevice.h \
    Include/libimobiledevice/installation_proxy.h \
    Include/libimobiledevice/house_arrest.h \
    Include/libimobiledevice/file_relay.h \
    Include/libimobiledevice/afc.h

LIBS += \
    Lib/libxml2 \
    Lib/imobiwin32.lib \
    Lib/libgcrypt.a \
    Lib/libgpg-error.a \
    Lib/glib-2.0.lib \
    Lib/gthread-2.0.lib
