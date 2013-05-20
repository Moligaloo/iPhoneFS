#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QMap>
#include <QLabel>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>

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
    ~MainWindow();

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

private:
    idevice_t device;
    lockdownd_client_t lockdownd;
    afc_client_t afc;

    QLabel *pathLabel;
    QListWidget *list;
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

signals:
    void deviceAdded();
    void deviceRemoved();
};

#endif // MAINWINDOW_H
