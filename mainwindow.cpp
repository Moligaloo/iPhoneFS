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

#include "libimobiledevice/installation_proxy.h"

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
        if(qstrcmp(filenames[i], ".") == 0)
            continue;

        if(qstrcmp(filenames[i], "..") == 0){
            new QListWidgetItem(QIcon("icon/folder.png"), "..", list);
            continue;
        }

        if(filenames[i][0] == '.' && !showHidden->isChecked())
            continue;

        FileInfo info;
        if(getFileInfo(filenames[i], &info)){
            new QListWidgetItem(QIcon(getIconPixmap(&info)), info.filename, list);
        }else{
            qDebug() << "failed to get info of " << filenames[i];
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

void MainWindow::showApplications(){
    uint16_t port = 0u;

    const char *service = "com.apple.mobile.installation_proxy";
    lockdownd_start_service(lockdownd, service , &port);
    if(port == 0){
        showWarning(tr("Start service %1 failed!").arg(service));
        return;
    }

    instproxy_client_t client = NULL;
    instproxy_client_new(device, port, &client);

    if(client == NULL){
        showWarning(tr("Create installation proxy failed!"));
        return;
    }

    plist_t options = instproxy_client_options_new();
    instproxy_client_options_add(options, "ApplicationType", "User", NULL);
    plist_t result = NULL;
    instproxy_browse(client, options,  &result);
    instproxy_client_options_free(options);

    if(result == NULL){
        showWarning(tr("Find apps failed"));
        return;
    }

    int n = plist_array_get_size(result);

    qDebug() << n;
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


        apps << displayNameString;
        free(displayNameString);
    }

    instproxy_client_free(client);
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
    QMenu *fileMenu = new QMenu(tr("File"));
    QAction *importAction = fileMenu->addAction(tr("Import file"));
    fileMenu->addSeparator();
    QAction *exitAction = fileMenu->addAction(tr("Exit"));
    menuBar->addMenu(fileMenu);
    setMenuBar(menuBar);

    connect(importAction, SIGNAL(triggered()), this, SLOT(importFile()));
    connect(exitAction, SIGNAL(triggered()), this, SLOT(close()));

    QMenu *viewMenu = new QMenu(tr("View"));
    showHidden = viewMenu->addAction(tr("Show hidden"));
    showHidden->setCheckable(true);

    QAction *showAppsAction = viewMenu->addAction(tr("Show applications"));
    connect(showAppsAction, SIGNAL(triggered()), this, SLOT(showApplications()));

    menuBar->addMenu(viewMenu);

    connect(showHidden, SIGNAL(toggled(bool)), this, SLOT(reload()));

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

    QMenu *aboutMenu = new QMenu(tr("About"));
    QAction *aboutProgram = aboutMenu->addAction(tr("About"));
    QAction *aboutQt = aboutMenu->addAction(tr("About Qt"));

    connect(aboutProgram, SIGNAL(triggered()), this, SLOT(aboutProgram()));
    connect(aboutQt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));

    menuBar->addMenu(aboutMenu);

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

    QWidget *widget = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout;
    layout->addWidget(pathLabel);
    layout->addWidget(list);
    widget->setLayout(layout);
    setCentralWidget(widget);

    device = NULL;
    lockdownd = NULL;
    afc = NULL;

    connect(this, SIGNAL(deviceAdded()), this, SLOT(onDeviceAdded()));
    connect(this, SIGNAL(deviceRemoved()), this, SLOT(onDeviceRemoved()));
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

    if(!items.isEmpty()){
        QMenu *menu = new QMenu(list);
        QAction *exportAction = menu->addAction(tr("Export"));
        QAction *removeAction = menu->addAction(tr("Remove"));
        QAction *makeDirectoryAction = menu->addAction(tr("Make Directory ..."));

        connect(exportAction, SIGNAL(triggered()), this, SLOT(exportFile()));
        connect(removeAction, SIGNAL(triggered()), this, SLOT(removeFile()));
        connect(makeDirectoryAction, SIGNAL(triggered()), this, SLOT(makeDirectory()));

        menu->popup(list->mapToGlobal(pos));
    }
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

void MainWindow::importFile(){
    QString filename = QFileDialog::getOpenFileName(this, tr("Select file to import"));
    if(filename.isEmpty())
        return;

    QFileInfo info(filename);
    QString filepath = getAbsoulteFilePath(info.fileName());
    uint64_t handle = 0;
    afc_file_open(afc, filepath.toLatin1().data(), AFC_FOPEN_WRONLY, &handle);

    if(handle == 0)
        return;

    QFile file(filename);
    if(file.open(QIODevice::ReadOnly)){
       QByteArray data = file.readAll();

       uint32_t bytes_written;
       afc_file_write(afc, handle, data.data(), data.size(), &bytes_written);
    }

    afc_file_close(afc, handle);

    reload();
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

void MainWindow::makeDirectory(){
    QString dirname = QInputDialog::getText(this, tr("Make directory"), tr("Please input the directory name:"), QLineEdit::Normal, tr("Directory"));
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
    QString filename = QFileDialog::getSaveFileName(this, tr("Select save file name"));
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

MainWindow::~MainWindow()
{
    afc_client_free(afc);
    lockdownd_client_free(lockdownd);
    idevice_free(device);
}
