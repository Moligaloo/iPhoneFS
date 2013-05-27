#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QMap>
#include <QLabel>
#include <QProgressBar>
#include <QThread>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>
#include "libimobiledevice/installation_proxy.h"

struct FileInfo;

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    MainWindow(QWidget *parent = 0);
    void emitDeviceAdded();
    void emitDeviceRemoved();
    void subscribeEvent();
    void showMessage(const QString &msg);

protected:
    void closeEvent(QCloseEvent *);

private slots:
    void onDeviceAdded();
    void onDeviceRemoved();
    void showContextMenu(const QPoint &pos);
    void importFile();
    void exportFile();
    void removeFile();
    void makeDirectory();
    void onItemDoubleClicked(QListWidgetItem *item);
    void showFileInfo(QListWidgetItem *item);
    void reload();
    void goRoot();
    void goParent();
    void goBookmark();
    void aboutProgram();
    void showApplications();
    void installApp();
    void archiveApp();
    void onInstallStarted();
    void onInstallFinished(int result);

private:
    idevice_t device;
    lockdownd_client_t lockdownd;
    afc_client_t afc;
    instproxy_client_t instproxy;

    QLabel *pathLabel;
    QListWidget *list;
    QLabel *progressLabel;
    QProgressBar *progressBar;
    QAction *showHidden;

    bool connectDevice();
    bool startLockdownd();
    bool startAFC2Service(uint16_t *afcPort);
    bool startAFC2Client(uint16_t afcPort);
    void enterDirectory(const QString &dirname);
    bool getFileInfo(const QString &filename, FileInfo *info);
    QPixmap getIconPixmap(FileInfo *info);
    QString getAbsoulteFilePath(const QString &filename) const;
    void exportFile(FileInfo *info);
    void setCurrentPath(const QString &path);
    void showWarning(const QString &message);
    void showInfo(const QString &message);
    bool setupInstproxy();
    bool copyFile(const QString &pcPath, const QString &devicePath);

signals:
    void deviceAdded();
    void deviceRemoved();
};

class InstallThread: public QThread{
    Q_OBJECT

public:
    InstallThread(instproxy_client_t client, const QString &afcPath);

private:
    instproxy_client_t client;
    QString afcPath;

    plist_t getInstallProxyOptions(const QString &metafile, const QString &sinffile);

protected:
    virtual void run();

signals:
    void finished(int result);
};

#endif // MAINWINDOW_H
