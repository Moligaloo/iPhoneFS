#include "mainwindow.h"

#include <QMessageBox>
#include <QFile>
#include <QtDebug>

#include <QTextEdit>
#include <QStatusBar>
#include <QMenuBar>
#include <QFileDialog>
#include <QVBoxLayout>
#include <QPainter>
#include <QInputDialog>
#include <QApplication>
#include <QStringListModel>
#include <QPushButton>

struct FileInfo{
    FileInfo(){
        size  = 0;
        isDirectory = false;
    }

    void readInfo(const QString &filename, char **info){
        this->filename = filename;

        int i;
        for(i=0; info[i]; i+=2){
            const char *key = info[i];
            const char *value = info[i+1];

            if(qstrcmp(key, "st_size") == 0)
                size = atoi(value);
            else if(qstrcmp(key, "st_ifmt") == 0)
                isDirectory = qstrcmp(value, "S_IFDIR") == 0;
            else if(qstrcmp(key, "LinkTarget") == 0)
                linkTarget = value;
        }
    }

    bool isLink() const{
        return !linkTarget.isEmpty();
    }

    QString toString() const{
        if(linkTarget.isEmpty())
            return QString("%1, size = %2").arg(filename).arg(size);
        else
            return QString("%1->%2, size = %3").arg(filename).arg(linkTarget).arg(size);
    }

    QString filename;
    int size;
    bool isDirectory;
    QString linkTarget;
};

static void callback(const idevice_event_t *event, void *data){
    MainWindow *window = (MainWindow *)data;
    if(event->event == IDEVICE_DEVICE_ADD){
        window->emitDeviceAdded();
    }else{
        window->emitDeviceRemoved();
    }
}

void MainWindow::onDeviceAdded(){
    showMessage(tr("Device added"));

    if(!connectDevice()){
        showMessage(tr("Device connection failed"));
        return;
    }

    if(!startLockdownd()){
        showMessage(tr("Lockdownd start error"));
        return;
    }

    uint16_t afcPort;

    if(!startAFC2Service(&afcPort)){
        QMessageBox::warning(this, tr("Warning"), tr("AFC2 service can not be started, your iPhone seems not jailbroken"));
        return;
    }

    if(!startAFC2Client(afcPort)){
        showMessage(tr("AFC2 client start failed"));
        return;
    }

    setCurrentPath("/");
}

bool MainWindow::connectDevice(){
    return idevice_new(&device, NULL) == IDEVICE_E_SUCCESS;
}

bool MainWindow::startLockdownd(){
    return lockdownd_client_new_with_handshake(device, &lockdownd, "baiduinputmethod") == LOCKDOWN_E_SUCCESS;
}

bool MainWindow::startAFC2Service(uint16_t *afcPort){
    return lockdownd_start_service(lockdownd, "com.apple.afc2", afcPort) == LOCKDOWN_E_SUCCESS;
}

bool MainWindow::startAFC2Client(uint16_t afcPort){
    return afc_client_new(device, afcPort, &afc) == AFC_E_SUCCESS;
}

QPixmap MainWindow::getIconPixmap(FileInfo *info){
    if(info->isLink()){
        FileInfo linkInfo;
        getFileInfo(info->linkTarget, &linkInfo);

        QPixmap pixmap = getIconPixmap(&linkInfo);
        QPixmap linkPixmap("icon/link.png");

        QPainter painter(&pixmap);
        painter.drawPixmap(0, 0, linkPixmap);
        return pixmap;
    }else{
        if(info->isDirectory)
            return QPixmap("icon/folder.png");
        else{
            if(info->filename.endsWith("png"))
                return QPixmap("icon/image.png");
            else
                return QPixmap("icon/file.png");
        }
    }
}

void MainWindow::setCurrentPath(const QString &path){
    QString currentPath = path;
    if(!currentPath.startsWith("/"))
        currentPath = "/" + currentPath;

    pathLabel->setText(currentPath);

    char **filenames = NULL;
    afc_error_t result = afc_read_directory(afc, currentPath.toUtf8().data(), &filenames);
    if(result != AFC_E_SUCCESS){
        showMessage(tr("Read directory %1 failed").arg(currentPath));
        return;
    }

    list->clear();
    int i;
    for(i=0; filenames[i]; i++){
        QString filename = filenames[i];

        if(filename == ".")
            continue;

        if(filename == ".."){
            new QListWidgetItem(QIcon("icon/folder.png"), "..", list);
            continue;
        }

        if(filename.startsWith(QChar('.')) && !showHidden->isChecked())
            continue;

        FileInfo info;
        if(getFileInfo(filename, &info)){
            new QListWidgetItem(QIcon(getIconPixmap(&info)), info.filename, list);
        }else{
            showWarning(tr("Failed to get file information of %1").arg(filename));
        }
    }
}

void MainWindow::enterDirectory(const QString &dirname){
    QStringList pathComponents = pathLabel->text().split("/", QString::SkipEmptyParts);
    if(dirname == ".."){
        if(pathComponents.isEmpty())
            return;

        pathComponents.removeLast();
    }else if(dirname != "/")
        pathComponents << dirname.split("/");

    setCurrentPath(pathComponents.join("/"));
}

void MainWindow::onDeviceRemoved(){
    showMessage(tr("Device removed"));
    list->clear();
    pathLabel->clear();
}

void MainWindow::emitDeviceAdded(){
    emit deviceAdded();
}

void MainWindow::emitDeviceRemoved(){
    emit deviceRemoved();
}

void MainWindow::aboutProgram(){
    QMessageBox::information(this, tr("About"), tr("This program is used to access files on jailbroken iPhone/iPod/iPad "));
}

void MainWindow::subscribeEvent(){
    idevice_event_subscribe(callback, this);
}

void MainWindow::showWarning(const QString &message){
    QMessageBox::warning(this, tr("Warning"), message);
}

void MainWindow::showInfo(const QString &message){
    QMessageBox::information(this, tr("Information"), message);
}

bool MainWindow::setupInstproxy(){
    if(instproxy == NULL){
        uint16_t port = 0u;

        const char *service = "com.apple.mobile.installation_proxy";
        lockdownd_error_t result =  lockdownd_start_service(lockdownd, service , &port);
        if(port == 0){
            showWarning(tr("Start service %1 failed! error code = %2").arg(service).arg(result));
            return false;
        }

        instproxy_client_new(device, port, &instproxy);
    }

    return instproxy != NULL;
}

InstallThread::InstallThread(instproxy_client_t client, const QString &afcPath):
    client(client), afcPath(afcPath)
{
}

void InstallThread::run(){
    plist_t options = getInstallProxyOptions("meta", "sinf");
    int result = instproxy_install(client, afcPath.toUtf8().data(), options, NULL, NULL);
    instproxy_client_options_free(options);

    emit finished(result);
}

plist_t InstallThread::getInstallProxyOptions(const QString &metafile, const QString &sinffile){
    plist_t sinf = NULL, meta = NULL;

    QFile file1(metafile);
    if(file1.open(QIODevice::ReadOnly)){
        QByteArray data = file1.readAll();
        sinf = plist_new_data(data.data(), data.length());
    }

    QFile file2(sinffile);
    if(file2.open(QIODevice::ReadOnly)){
        QByteArray data = file2.readAll();
        meta = plist_new_data(data.data(), data.length());
    }

    if(sinf || meta){
        plist_t options = instproxy_client_options_new();
        if(sinf)
            instproxy_client_options_add(options, "ApplicationSINF", sinf, NULL);

        if(meta)
            instproxy_client_options_add(options, "iTunesMetaData", meta, NULL);

        return options;
    }else
        return NULL;
}

void MainWindow::onInstallStarted(){
    progressLabel->setText(tr("Install app"));
    progressBar->setRange(0, 0);
    progressBar->setValue(0);

    progressLabel->show();
    progressBar->show();
}

void MainWindow::onInstallFinished(int result){
    progressLabel->hide();
    progressBar->hide();

    if(result == INSTPROXY_E_SUCCESS){
        showInfo(tr("Install success"));
    }else{
        showWarning(tr("Install failed! error code = %1").arg(result));
    }

    InstallThread *thread = qobject_cast<InstallThread *>(sender());
    thread->deleteLater();
}

void MainWindow::installApp(){
    if(!setupInstproxy()){
        return;
    }

    QString ipaFile = QFileDialog::getOpenFileName(this,
                                                   tr("Select an IPA file"),
                                                   QString(),
                                                   tr("IPA file (*.ipa)"));

    if(ipaFile.isEmpty())
        return;

    QFileInfo info(ipaFile);
    QString afc2Path = QString("/var/mobile/Media/PublicStaging/%1").arg(info.fileName());
    copyFile(ipaFile, afc2Path)->setShouldInstall(true);
}

void MainWindow::installIPAFile(const QString &afcPath){
    InstallThread *thread = new InstallThread(instproxy, afcPath);
    connect(thread, SIGNAL(started()), this, SLOT(onInstallStarted()));
    connect(thread, SIGNAL(finished(int)), this, SLOT(onInstallFinished(int)));

    thread->start();
}

void MainWindow::archiveApp(){
    QString appid = QInputDialog::getText(this,
                                          tr("Archive app"),
                                          tr("Please input app's id"),
                                          QLineEdit::Normal,
                                          tr("Appid"));

    if(appid.isEmpty()){
        return;
    }

    if(!setupInstproxy()){
        return;
    }

    Q_ASSERT(instproxy);

    const char *app = appid.toUtf8().data();
    instproxy_error_t result = instproxy_archive(instproxy, app, NULL, NULL, NULL);
    if(result == INSTPROXY_E_SUCCESS){
        showInfo(tr("App %1 has been archived into /ApplicationArchives/%1.zip").arg(appid));
    }else{
        showWarning(tr("Archive %1 failed, error code = %2").arg(appid).arg(result));
    }
}

void MainWindow::showApplications(){
    if(!setupInstproxy()){
        return;
    }

    plist_t options = instproxy_client_options_new();
    instproxy_client_options_add(options, "ApplicationType", "User", NULL);
    plist_t result = NULL;
    instproxy_browse(instproxy, options,  &result);
    instproxy_client_options_free(options);

    if(result == NULL){
        showWarning(tr("Find apps failed"));
        return;
    }

    int n = plist_array_get_size(result);

    QStringList apps;
    for(int i=0; i<n; i++){
        plist_t app = plist_array_get_item(result, i);
        if(app == NULL)
            continue;

        plist_t displayName = plist_dict_get_item(app, "CFBundleDisplayName");
        if(displayName == NULL)
            continue;

        char *displayNameString = NULL;
        plist_get_string_val(displayName, &displayNameString);

        plist_t appid = plist_dict_get_item(app, "CFBundleIdentifier");
        if(appid == NULL)
            continue;

        char *appidString = NULL;
        plist_get_string_val(appid, &appidString);

        apps << QString("%1 (%2)").arg(displayNameString).arg(appidString);
        free(displayNameString);
        free(appidString);
    }

    plist_free(result);

    QListView *list = new QListView;
    list->setModel(new QStringListModel(apps, list));

    list->show();
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    resize(800, 600);

    QMenuBar *menuBar = new QMenuBar;

    {

        QMenu *fileMenu = new QMenu(tr("File"));
        QAction *importAction = fileMenu->addAction(tr("Import file"));
        fileMenu->addSeparator();
        QAction *exitAction = fileMenu->addAction(tr("Exit"));
        menuBar->addMenu(fileMenu);
        setMenuBar(menuBar);

        connect(importAction, SIGNAL(triggered()), this, SLOT(importFile()));
        connect(exitAction, SIGNAL(triggered()), this, SLOT(close()));
    }

    {
        QMenu *viewMenu = new QMenu(tr("View"));
        showHidden = viewMenu->addAction(tr("Show hidden"));
        showHidden->setCheckable(true);

        menuBar->addMenu(viewMenu);

        connect(showHidden, SIGNAL(toggled(bool)), this, SLOT(reload()));
    }

    {
        QMenu *menu = new QMenu("Application");
        QAction *show = menu->addAction(tr("List"));
        QAction *install = menu->addAction(tr("Install"));
        QAction *archive = menu->addAction(tr("Archive ..."));

        connect(show, SIGNAL(triggered()), this, SLOT(showApplications()));
        connect(install, SIGNAL(triggered()), this, SLOT(installApp()));
        connect(archive, SIGNAL(triggered()), this, SLOT(archiveApp()));

        menuBar->addMenu(menu);
    }

    {
        QMenu *navigateMenu = new QMenu(tr("Navigate"));
        QAction *goParent = navigateMenu->addAction(tr("Parent"));
        QAction *goRoot = navigateMenu->addAction(tr("Root"));
        navigateMenu->addSeparator();
        connect(goParent, SIGNAL(triggered()), this, SLOT(goParent()));
        connect(goRoot, SIGNAL(triggered()), this, SLOT(goRoot()));

        QStringList bookmarks;
        bookmarks << "/var/root/Media/Cydia/AutoInstall" << "/var/mobile/Library/Keyboard/BaiduInputMethod";

        foreach(QString bookmark, bookmarks){
            QAction *action = navigateMenu->addAction(bookmark);
            connect(action, SIGNAL(triggered()), this, SLOT(goBookmark()));
        }

        menuBar->addMenu(navigateMenu);
    }

    {
        QMenu *aboutMenu = new QMenu(tr("About"));
        QAction *aboutProgram = aboutMenu->addAction(tr("About"));
        QAction *aboutQt = aboutMenu->addAction(tr("About Qt"));

        connect(aboutProgram, SIGNAL(triggered()), this, SLOT(aboutProgram()));
        connect(aboutQt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));

        menuBar->addMenu(aboutMenu);
    }

    list = new QListWidget;
    list->setViewMode(QListWidget::IconMode);
    list->setIconSize(QSize(64, 64));
    list->setMovement(QListWidget::Static);
    list->setContextMenuPolicy(Qt::CustomContextMenu);
    list->setGridSize(QSize(80, 100));

    connect(list, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showContextMenu(QPoint)));
    connect(list, SIGNAL(itemClicked(QListWidgetItem*)), this, SLOT(showFileInfo(QListWidgetItem*)));
    connect(list, SIGNAL(itemDoubleClicked(QListWidgetItem*)), this, SLOT(onItemDoubleClicked(QListWidgetItem*)));

    QStatusBar *statusBar = new QStatusBar();
    setStatusBar(statusBar);

    showMessage(tr("Waiting for device connection"));

    pathLabel = new QLabel;
    progressLabel = new QLabel;
    progressBar = new QProgressBar;

    QWidget *widget = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout;
    layout->addWidget(pathLabel);
    layout->addWidget(list);
    layout->addWidget(progressLabel);
    layout->addWidget(progressBar);

    widget->setLayout(layout);
    setCentralWidget(widget);

    device = NULL;
    lockdownd = NULL;
    afc = NULL;
    instproxy = NULL;

    connect(this, SIGNAL(deviceAdded()), this, SLOT(onDeviceAdded()));
    connect(this, SIGNAL(deviceRemoved()), this, SLOT(onDeviceRemoved()));

    progressLabel->hide();
    progressBar->hide();
}

void MainWindow::goBookmark(){
    QAction *action = qobject_cast<QAction *>(sender());
    if(action){
        QString dirname = action->text();
        setCurrentPath(dirname);
    }
}

void MainWindow::goRoot(){
    setCurrentPath("/");
}

void MainWindow::goParent(){
    enterDirectory("..");
}

void MainWindow::showContextMenu(const QPoint &pos){
    QList<QListWidgetItem *> items = list->selectedItems();

    QMenu *menu = new QMenu(list);
    if(items.isEmpty()){
        QAction *makeDirectoryAction = menu->addAction(tr("Make Directory ..."));
        QAction *reloadAction = menu->addAction(tr("Reload"));

        connect(makeDirectoryAction, SIGNAL(triggered()), this, SLOT(makeDirectory()));
        connect(reloadAction, SIGNAL(triggered()), this, SLOT(reload()));
    }else{
        QAction *exportAction = menu->addAction(tr("Export"));
        QAction *removeAction = menu->addAction(tr("Remove"));
        QAction *renameAction = menu->addAction(tr("Rename"));

        connect(exportAction, SIGNAL(triggered()), this, SLOT(exportFile()));
        connect(removeAction, SIGNAL(triggered()), this, SLOT(removeFile()));
        connect(renameAction, SIGNAL(triggered()), this, SLOT(renameFile()));
    }

    menu->popup(list->mapToGlobal(pos));
}

QString MainWindow::getAbsoulteFilePath(const QString &filename) const{
    if(filename.startsWith("/"))
        return filename;
    else{
        QString currentPath = pathLabel->text();
        if(currentPath.endsWith("/"))
            return currentPath.append(filename);
        else
            return QString("%1/%2").arg(pathLabel->text()).arg(filename);
    }
}

bool MainWindow::getFileInfo(const QString &filename, FileInfo *info){
    QString filepath = getAbsoulteFilePath(filename);

    char **infolist = NULL;
    afc_error_t result = afc_get_file_info(afc, filepath.toUtf8(), &infolist);

    if(result != AFC_E_SUCCESS)
        return false;
    else{
        info->readInfo(filename, infolist);
        return true;
    }
}

void MainWindow::showFileInfo(QListWidgetItem *item){
    FileInfo info;
    if(getFileInfo(item->text(), &info)){
        showMessage(info.toString());
    }
}

void MainWindow::onItemDoubleClicked(QListWidgetItem *item){
    FileInfo info;
    if(getFileInfo(item->text(), &info)){
        if(info.isDirectory || info.isLink())
            enterDirectory(item->text());
        else
            exportFile(&info);
    }
}

CopyThread::CopyThread(afc_client_t afc, const QString &pcPath, const QString &devicePath)
    :afc(afc), pcPath(pcPath), devicePath(devicePath), shouldInstall(false)
{

}

QString CopyThread::afcPath() const{
    QFileInfo info(pcPath);
    return QString("PublicStaging/%1").arg(info.fileName());
}

void CopyThread::run(){
    QFile file(pcPath);
    if(!file.open(QIODevice::ReadOnly)){
        emit copyFinished(1);
        return;
    }

    uint64_t handle = 0;
    afc_file_open(afc, devicePath.toUtf8().data(), AFC_FOPEN_WRONLY, &handle);
    if(handle == 0){
        emit copyFinished(2);
        return;
    }

    const int blockSize = 10 * 1024; // 10k

    const QString prompt = tr("Copy %1 to %2").arg(pcPath).arg(devicePath);
    const int blockCount = file.size() / blockSize;

    emit copyStarted(prompt, blockCount);

    for(int i=0; !file.atEnd(); i++){
        emit copyProgress(i);

        QByteArray data = file.read(blockSize);
        uint32_t bytes_written;
        afc_error_t result = afc_file_write(afc, handle, data.data(), data.size(), &bytes_written);
        if(result != AFC_E_SUCCESS){
            afc_file_close(afc, handle);
            emit copyFinished(result);
            break;
        }
    }

    emit copyFinished(afc_file_close(afc, handle));
}

CopyThread *MainWindow::copyFile(const QString &pcPath, const QString &devicePath){
    CopyThread *thread = new CopyThread(afc, pcPath, devicePath);

    progressLabel->setText(tr("Copy %1 to %2").arg(pcPath).arg(devicePath));

    connect(thread, SIGNAL(copyStarted(QString,int)), this, SLOT(onCopyStarted(QString,int)));
    connect(thread, SIGNAL(copyProgress(int)), progressBar, SLOT(setValue(int)));
    connect(thread, SIGNAL(copyFinished(int)), this, SLOT(onCopyFinished(int)));

    thread->start();

    return thread;
}

void MainWindow::onCopyStarted(const QString &prompt, int blockCount){
    progressLabel->setText(prompt);
    progressBar->setRange(0, blockCount);
    progressBar->setValue(0);

    progressLabel->show();
    progressBar->show();
}

void MainWindow::onCopyFinished(int result){
    if(result != 0){
        showWarning(tr("Copy failed with result %1").arg(result));
    }

    progressLabel->hide();
    progressBar->hide();


    CopyThread *thread = qobject_cast<CopyThread *>(sender());
    if(thread){
        if(thread->isShouldInstall())
            installIPAFile(thread->afcPath());
        else
            reload();

        thread->deleteLater();
    }
}

void MainWindow::importFile(){
    QString filename = QFileDialog::getOpenFileName(this, tr("Select file to import"));
    if(filename.isEmpty())
        return;

    QFileInfo info(filename);
    QString filepath = getAbsoulteFilePath(info.fileName());

    copyFile(filename, filepath);
}

void MainWindow::reload(){
    setCurrentPath(pathLabel->text());
}

void MainWindow::exportFile(){
    QList<QListWidgetItem *> items = list->selectedItems();
    if(!items.isEmpty()){
        QListWidgetItem *item = items.first();
        FileInfo info;
        if(getFileInfo(item->text(), &info)){
            exportFile(&info);
        }
    }
}

void MainWindow::removeFile(){
    QList<QListWidgetItem *> items = list->selectedItems();
    if(!items.isEmpty()){
        QListWidgetItem *item = items.first();
        FileInfo info;
        if(getFileInfo(item->text(), &info)){
            QString filepath = getAbsoulteFilePath(info.filename);
            afc_remove_path(afc, filepath.toLatin1().data());
            reload();
        }
    }
}

void MainWindow::renameFile(){
    QString oldname = list->selectedItems().first()->text();
    QString newname = QInputDialog::getText(this,
                                            tr("Rename"),
                                            tr("Please input the new name of %1").arg(oldname));

    if(newname.isEmpty() || newname == oldname)
        return;

    QString from = QString("%1/%2").arg(pathLabel->text()).arg(oldname);
    QString to = QString("%1/%2").arg(pathLabel->text()).arg(newname);
    afc_error_t result = afc_rename_path(afc, from.toUtf8().data(), to.toUtf8().data());
    if(result == AFC_E_SUCCESS)
        showMessage(tr("Rename success"));
    else
        showWarning(tr("Rename failed!"));

    reload();
}

void MainWindow::makeDirectory(){
    QString dirname = QInputDialog::getText(this,
                                            tr("Make directory"),
                                            tr("Please input the directory name:"),
                                            QLineEdit::Normal,
                                            tr("NewFolder"));

    if(!dirname.isEmpty()){
        QString dirpath = getAbsoulteFilePath(dirname);
        afc_error_t result = afc_make_directory(afc, dirpath.toUtf8().data());
        if(result == AFC_E_SUCCESS)
            reload();
        else
            QMessageBox::warning(this, tr("Error"), tr("Make directory %1 error").arg(dirname));
    }
}

void MainWindow::exportFile(FileInfo *info){
    QString filename = QFileDialog::getSaveFileName(this, tr("Select save file name"), info->filename);
    if(filename.isEmpty())
        return;

    QString filepath = getAbsoulteFilePath(info->filename);

    uint64_t handle = 0u;
    afc_file_open(afc, filepath.toUtf8().data(), AFC_FOPEN_RDONLY, &handle);

    if(handle == 0){
        QMessageBox::warning(this, tr("Export error"), tr("File %1 can not be opened from iOS device").arg(filepath));
        return;
    }

    char *data = new char[info->size];

    uint32_t bytes_read = 0;
    afc_error_t result = afc_file_read(afc, handle, data, info->size, &bytes_read);
    if(result == AFC_E_SUCCESS){
        QFile file(filename);
        if(file.open(QIODevice::WriteOnly)){
            file.write(data, info->size);
        }
    }else{
        QMessageBox::warning(this, tr("Export error"), tr("Export file %1 failed").arg(filename));
    }

    delete[] data;
    afc_file_close(afc, handle);
}

void MainWindow::showMessage(const QString &msg){
    //qDebug() << msg;
    statusBar()->showMessage(msg);
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    QMainWindow::closeEvent(e);

    afc_client_free(afc);
    instproxy_client_free(instproxy);
    lockdownd_client_free(lockdownd);
    idevice_free(device);

    qApp->quit();
}

