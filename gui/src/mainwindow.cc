
/*!
 * \file mainwindow.cc
 * \brief Main window for Pombo GUI.
 * \author BoboTiG
 * \date 2013.06.06
 *
 * Copyleft ((C)) 2013 BoboTiG
 */


#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    settings(new QSettings(CONFIG_FILE, QSettings::IniFormat))
{}


MainWindow::~MainWindow() {
    delete settings;
    delete ui;
}


/**
 * @brief Création de l'interface graphique et chargement des paramètres de Pombo.
 * @date 2013/07/11
 */
void MainWindow::init() {
    ui->setupUi(this);
    ui->statusBar->setSizeGripEnabled(false);
    if ( ui->tabWidget->currentIndex() != 0 ) {
         ui->tabWidget->setCurrentIndex(0);
    }
    ui->normalSlider->setMinimum(TIME_NORMAL_MIN);
    ui->normalSlider->setMaximum(TIME_NORMAL_MAX);

#ifndef _WIN32
    ui->cmdLineEdit4->setToolTip(tr("<i>&lt;user&gt;</i> will be replaced by the username, <i>&lt;filepath&gt;</i> by the output filename."));
    ui->cmdLineEdit5->setToolTip(tr("<i>&lt;filepath&gt;</i> will be replaced by the output filename."));
#endif

    // Centrage de la fenêtre
    QRect availableGeometry(QApplication::desktop()->availableGeometry());
    move((availableGeometry.width() - width()) / 2,
         (availableGeometry.height() - height()) / 2);

    // Lecture du fichier de configuration
    loadConfiguration();

#ifndef _WIN32
    // Lecture du fichier de commandes prédéfinies
    loadPredefinedCmd();
#endif

    // Testeurs et contributeurs (par ordre alphabétique)
    helpers["Sébastien Sauvage"] = "http://www.sebsauvage.net/pombo/";
    helpers["mohican"]           = "http://doc.ubuntu-fr.org/utilisateurs/mohican";
    helpers["solsTiCe d'Hiver"]  = "https://github.com/solsticedhiver/pombo_on_appengine";
    helpers["Timo van Neerden"]  = "http://lehollandaisvolant.net/";
    helpers["Timothée Laisne"]   = "http://geekdefrance.fr/";
    helpers["tuxmouraille"]      = "https://github.com/tuxmouraille/MesApps/tree/master/Pombo";
    helpers["Stéphane Jouin"]    = "http://www.jouin.eu/";
    helpers["Romain 'tsyr2ko' Carbonnel"] = "https://github.com/rcarbonnel";

    ui->statusBar->showMessage(tr("Welcome :)"), 5000);
}


/**
 * @brief Chargement des paramètres contenus dans le fichier de configuration.
 * @date 2013/06/05
 */
void MainWindow::loadConfiguration() {
#ifndef _WIN32
    ui->actionFolder->setVisible(false);
#endif
    ui->statusBar->showMessage(tr("Loading the configuration ..."));
    if ( settings->status() == QSettings::NoError ) {
        // Informations générales
        unsigned int time_limit = settings->value("time_limit").toInt();
        if ( time_limit < 15 ) {
             time_limit = 15;
        }
        ui->gpgkeyidLineEdit->setText(settings->value("gpgkeyid").toString());
        ui->passwordLineEdit->setText(settings->value("password").toString());
        ui->serverTextEdit->setText(QStringList(settings->value("server_url").toString().split("|")).join("\n"));
        ui->checkfileLineEdit->setText(settings->value("check_file").toString());
        ui->onlyOnIPChangeCheckBox->setChecked(settings->value("only_on_ip_change").toBool());
        ui->emailLineEdit->setText(settings->value("email_id").toString());
        ui->normalSlider->setValue(time_limit);
        ui->checkBoxEnableLog->setChecked(settings->value("enable_log").toBool());
        ui->stolenLabel->setText(tr("When stolen, each report will be spaced %1 min.").arg(QString::number(time_limit / 3)));
        ui->groupBoxProxy->setChecked(settings->value("use_proxy").toBool());
        ui->useEnvironnementVarsCheckBox->setChecked(settings->value("use_env").toBool());
        ui->hTTPProxyLineEdit->setText(settings->value("http_proxy").toString());
        ui->hTTPSProxyLineEdit->setText(settings->value("https_proxy").toString());
        ui->groupBoxBasicAuth->setChecked(settings->value("auth_server").toString() != "");
        ui->domainLineEditBasicAuth->setText(settings->value("auth_server").toString());
        ui->usernameLineEditBasicAuth->setText(settings->value("auth_user").toString());
        ui->passwordLineEditBasicAuth->setText(settings->value("auth_pswd").toString());

        // Commandes
        QStringList commands, fileTypes;
        fileTypes << "bmp" << "jpeg" << "png" << "ppm" << "tiff";
        settings->beginGroup("Commands");
        commands << settings->value("network_config").toString();
        commands << settings->value("wifi_access_points").toString();
        commands << settings->value("traceroute").toString();
        commands << settings->value("network_trafic").toString();
        commands << settings->value("screenshot").toString();
        commands << settings->value("camshot").toString();
        commands << settings->value("camshot_filetype").toString();
        settings->endGroup();
        unsigned int i, total = commands.count() - 1;
        for ( i = 0; i < total; ++i ) {
            if ( commands.at(i) == "" ) {
                QString check = "check" + QString::number(i);
                QGroupBox *group = findChild<QGroupBox*>(check);
                group->setChecked(false);
            } else {
                QString text = "cmdLineEdit" + QString::number(i);
                QLineEdit *line = findChild<QLineEdit*>(text);
                line->setText(commands.at(i));
            }
        }
        int  index = fileTypes.indexOf(commands.at(i));
        if ( index == -1 ) {
             index = 1;
        }
        ui->comboBoxWebcamFiletype->setCurrentIndex(index);
#ifdef _WIN32
        ui->cmdLineEdit4->setEnabled(false);
        ui->pushButtonResetCmd4->setEnabled(false);
        ui->cmdLineEdit5->setEnabled(false);
        ui->pushButtonResetCmd5->setEnabled(false);
        ui->filetypeLabel->setEnabled(false);
        ui->comboBoxWebcamFiletype->setEnabled(false);
        ui->cmdLineEdit4->setToolTip(tr("Functionality automatically handled on Windows, only need to check the checkbox."));
        ui->cmdLineEdit5->setToolTip(tr("Functionality automatically handled on Windows, only need to check the checkbox."));
#endif
        ui->statusBar->showMessage(tr("Configuration loaded!"));
    } else {
        youShallNotPass(strerror(settings->status()));
        ui->actionSave->setEnabled(0);
        ui->tabGeneral->setEnabled(0);
        ui->tabAuth->setEnabled(0);
        ui->tabCommands->setEnabled(0);
    }
}


/**
 * @brief Chargement des commandes prédéfinies.
 * @date 2013/06/03
 */
#ifndef _WIN32
void MainWindow::loadPredefinedCmd() {
    QSettings choices(CMD_LIST, QSettings::IniFormat);
    if ( choices.status() == QSettings::NoError ) {
        QStringList commands;
        unsigned int i, total;

        choices.beginGroup("screenshot");
        commands = choices.childKeys();
        total = commands.count();
        for ( i = 0; i < total; ++i ) {
            cmd_screenshot_choices << choices.value(commands.at(i)).toString();
        }
        choices.endGroup();

        choices.beginGroup("webcamshot");
        commands = choices.childKeys();
        total = commands.count();
        for ( i = 0; i < total; ++i ) {
            cmd_webcamshot_choices << choices.value(commands.at(i)).toString();
        }
        choices.endGroup();
    } else {
        youShallNotPass(strerror(choices.status()));
    }
}
#endif


/**
 * @brief Ouvrir une URL suivant le testeur/contributeur sélectionné.
 * @date 2013/05/23
 */
void MainWindow::open_url_tester_contributor(const QModelIndex &index) {
    std::string human = index.data().toString().toStdString();
    std::map<std::string,std::string>::iterator it = helpers.find(human);
    if (  it != helpers.end() ) {
        QString url = it->second.c_str() + QString("?&ref=pombo-config");
        QDesktopServices::openUrl(QUrl(url));
    }
}


/**
 * @brief Mise en place du nouveau fichier de lancment cron.
 * @date 2013/05/24
 */
#ifndef _WIN32
int MainWindow::updateCron(unsigned int new_time_limit) {
    FILE* config = fopen(CRON_FILE, "w");

    if ( config != NULL ) {
        char* line = new char[128];
        sprintf(line, CRON_LINE, new_time_limit);
        fwrite(line, 1, strlen(line), config);
        fclose(config);
        delete[] line;
    }
    return errno;
}
#endif


/**
 * @brief Message d'erreur critique si je n'arrive pas à ouvrir le fichier.
 * @date 2013/05/15
 */
void MainWindow::youShallNotPass(const QString &err) {
    QMessageBox::critical(this, tr("Oups!"),
                          tr("Error while trying to open the configuration file:")
                          + "<br /><b>" + err + "</b>");
}


/*
 **** Actions ****
 */

// Barre d'outils
/**
 * @brief Action à effectuer lorsque l'icône "Dossier" a été activée.
 * @date 2013/06/06
 */
void MainWindow::on_actionFolder_triggered() {
#ifdef _WIN32
    QString path = QString("file:///") + POMBO_FOLDER;
    QDesktopServices::openUrl(QUrl(path));
#endif
}


/**
 * @brief Action à effectuer lorsque l'icône "Enregistrer" a été activée.
 * @date 2013/06/05
 */
void MainWindow::on_actionSave_triggered() {
    ui->statusBar->showMessage(tr("Saving the configuration ..."));
    // Récupération de tous les paramètres
    unsigned int time_limit_original = settings->value("time_limit").toInt();
    unsigned int time_limit_modified = ui->normalSlider->value();
    // Informations générales
    settings->setValue("gpgkeyid",          ui->gpgkeyidLineEdit->text());
    settings->setValue("password",          ui->passwordLineEdit->text());
    settings->setValue("server_url",        QStringList(ui->serverTextEdit->toPlainText().split("\n")).join("|"));
    settings->setValue("check_file",        ui->checkfileLineEdit->text());
    settings->setValue("only_on_ip_change", ui->onlyOnIPChangeCheckBox->isChecked());
    settings->setValue("email_id",          ui->emailLineEdit->text());
    settings->setValue("use_proxy",         ui->groupBoxProxy->isChecked());
    settings->setValue("use_env",           ui->useEnvironnementVarsCheckBox->isChecked());
    settings->setValue("http_proxy",        ui->hTTPProxyLineEdit->text());
    settings->setValue("https_proxy",       ui->hTTPSProxyLineEdit->text());
    settings->setValue("time_limit",        time_limit_modified);
    settings->setValue("enable_log",        ui->checkBoxEnableLog->isChecked());
    if ( ui->groupBoxBasicAuth->isChecked() ) {
        settings->setValue("auth_server",   ui->domainLineEditBasicAuth->text());
        settings->setValue("auth_user",     ui->usernameLineEditBasicAuth->text());
        settings->setValue("auth_pswd",     ui->passwordLineEditBasicAuth->text());
    } else {
        settings->setValue("auth_server","");
        settings->setValue("auth_user",  "");
        settings->setValue("auth_pswd",  "");
    }
    // Commandes
    QStringList commands, fileTypes;
    fileTypes << "bmp" << "jpeg" << "png" << "ppm" << "tiff";
    commands << "network_config";
    commands << "wifi_access_points";
    commands << "traceroute";
    commands << "network_trafic";
    commands << "screenshot";
    commands << "camshot";
    commands << "camshot_filetype";

    settings->beginGroup("Commands");
    unsigned int i, total = commands.count() - 1;
    for ( i = 0; i < total; ++i ) {
        QString check = "check" + QString::number(i);
        QGroupBox *group = findChild<QGroupBox*>(check);
        if ( group->isChecked() ) {
            QString text = "cmdLineEdit" + QString::number(i);
            QLineEdit *line = findChild<QLineEdit*>(text);
            settings->setValue(commands.at(i), line->text());
        } else {
            settings->setValue(commands.at(i), "");
        }
    }
    settings->setValue(commands.at(i), fileTypes.at(ui->comboBoxWebcamFiletype->currentIndex()));
    settings->endGroup();

    // Synchronisation avec le fichier et vérification du bon déroulement des opérations
    settings->sync();
    if ( settings->status() != QSettings::NoError ) {
        QString title = tr("Oups!");
        QString text  = tr("Error while trying to save the configuration file:");
        QString err   = tr("An access error occurred (e.g. trying to write to a read-only file).");

        if ( settings->status() == QSettings::AccessError ) {
            err = tr("A format error occurred (e.g. loading a malformed INI file).");
        }
        QMessageBox::critical(this, title, text + "<br /><b>" + err + "</b>");
        ui->statusBar->showMessage(text + "<b>" + err + "</b>");
    } else {
        ui->statusBar->showMessage(tr("Configuration saved with success!"), 3000);
    }
#ifndef _WIN32
    // MàJ de /etc/cron.d/pombo si modification il y a
    if ( time_limit_original != time_limit_modified ) {
        int ret = updateCron(time_limit_modified);
        if ( ret ) {
            ui->statusBar->showMessage(QString(CRON_FILE) + " : " + strerror(ret));
            return;
        }
    }
#endif
}


/**
 * @brief Action à effectuer lorsque l'icône "Projet" a été activée.
 * @date 2013/05/16
 */
void MainWindow::on_actionProject_triggered() {
    QDesktopServices::openUrl(QUrl(WEBSITE));
}


/**
 * @brief Action à effectuer lorsque l'icône "Quitter" a été activée.
 * @date 2013/05/15
 */
void MainWindow::on_action_Exit_triggered() {
    close();
}


// Onglet "Général"
/**
 * @brief Action à effectuer lorsque l'édition du champ "Clef GPG" est terminée.
 * @date 2013/05/16
 */
void MainWindow::on_gpgkeyidLineEdit_editingFinished() {
    QRegExp keyFormat("^[0-9a-fA-F]{8}$");
    if ( !ui->gpgkeyidLineEdit->text().contains(keyFormat) ) {
        ui->statusBar->showMessage(tr("Hm ... Your 'GPG key ID' does not consist of 8 hex digits."));
    } else {
        if ( ui->statusBar->currentMessage() == tr("Hm ... Your 'GPG key ID' does not consist of 8 hex digits.") ) {
            ui->statusBar->showMessage(tr("What else?"), 2000);
        }
    }
}


/**
 * @brief Action à effectuer lorsque le slider "en temps normal" est modifié.
 * @date 2013/05/20
 */
void MainWindow::on_normalSlider_valueChanged(int value) {
    ui->normalNumber->setText(QString::number(value));
    ui->stolenLabel->setText(tr("When stolen, each report will be spaced %1 min.").arg(QString::number(value / 3)));
}


// Onglet "Authentification"
/**
 * @brief Action à effectuer lorsque la case à cocher "Utiliser les variables d'environnement" est modifiée.
 * @date 2013/06/01
 */
void MainWindow::on_useEnvironnementVarsCheckBox_stateChanged(int state) {
    ui->hTTPProxyLabel->setEnabled(!state);
    ui->hTTPSProxyLabel->setEnabled(!state);
    ui->hTTPProxyLineEdit->setEnabled(!state);
    ui->hTTPSProxyLineEdit->setEnabled(!state);
}


// Onglet "Commandes"
/**
* @brief Actions pour restaurer les commandes par défaut.
* @date 2013/06/03
*/
void MainWindow::on_pushButtonResetCmd0_clicked() {
    ui->cmdLineEdit0->setText(CMD_NETWORK);
}
void MainWindow::on_pushButtonResetCmd1_clicked() {
    ui->cmdLineEdit1->setText(CMD_WIRELESS);
}
void MainWindow::on_pushButtonResetCmd2_clicked() {
    ui->cmdLineEdit2->setText(CMD_TRACERT);
}
void MainWindow::on_pushButtonResetCmd3_clicked() {
    ui->cmdLineEdit3->setText(CMD_NETTRAFIC);
}


/**
* @brief Actions pour le choix d'une commande prédéfinie.
* @date 2013/06/03
*/
void MainWindow::on_pushButtonResetCmd4_clicked() {
#ifndef _WIN32
    bool ok;
    QString choice = QInputDialog::getItem(
                this, tr("Pombo - Screenshot"), tr("Choose a predefined command:"),
                cmd_screenshot_choices, 0, false, &ok);

    if ( ok && !choice.isEmpty() ) {
        ui->cmdLineEdit4->setText(choice);
    }
#endif
}
void MainWindow::on_pushButtonResetCmd5_clicked() {
#ifndef _WIN32
    bool ok;
    QString choice = QInputDialog::getItem(
                this, tr("Pombo - Webcam shot"), tr("Choose a predefined command:"),
                cmd_webcamshot_choices, 0, false, &ok);

    if ( ok && !choice.isEmpty() ) {
        ui->cmdLineEdit5->setText(choice);
    }
#endif
}


// Onglet "Plus"
/**
 * @brief Action à effectuer lorsque l'icône de Pombo est cliquée.
 * @date 2013/05/23
 */
void MainWindow::on_pushButtonOfficialWebsite_clicked() {
    QDesktopServices::openUrl(QUrl(WEBSITE));
}


/**
 * @brief Action à effectuer lors d'un double-clic sur un contributeur.
 * @date 2013/05/23
 */
void MainWindow::on_listWidgetHelpers_doubleClicked(const QModelIndex &index) {
    open_url_tester_contributor(index);
}


/**
 * @brief Action à effectuer lors d'un appui sur Entrée sur un contributeur.
 * @date 2013/05/23
 */
void MainWindow::on_listWidgetHelpers_entered(const QModelIndex &index) {
    open_url_tester_contributor(index);
}
