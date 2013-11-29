
/*!
 * \file mainwindow.h
 * \brief Main window headers for Pombo GUI.
 * \author BoboTiG
 * \date 2013.06.25
 *
 * Copyleft ((C)) 2013 BoboTiG
 */


#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QApplication>
#include <QTextCodec>
#include <QMainWindow>
#include <QDesktopWidget>
#include <QMessageBox>
#include <QTranslator>
#include <QLocale>
#include <QSettings>
#include <QStringList>
#include <QDesktopServices>
#include <QUrl>
#include <QModelIndex>
#include <QInputDialog>

#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    #include <QCleanlooksStyle>
#endif

#ifndef _WIN32
    #include <cerrno>
#endif
#include <cstdio>

#include "constants.h"


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void init();
    void youShallNotPass(const QString &err);
    
private slots:
    // Barre d'outils
    void on_actionFolder_triggered();
    void on_actionSave_triggered();
    void on_actionProject_triggered();
    void on_action_Exit_triggered();
    // Onglet "Général"
    void on_gpgkeyidLineEdit_editingFinished();
    void on_normalSlider_valueChanged(int value);
    // Onglet "Authentification"
    void on_useEnvironnementVarsCheckBox_stateChanged(int state);
    // Onglet "Commandes"
    void on_pushButtonResetCmd0_clicked();  // Réseau
    void on_pushButtonResetCmd1_clicked();  // WiFi
    void on_pushButtonResetCmd2_clicked();  // Traceroute
    void on_pushButtonResetCmd3_clicked();  // Trafic réseau
    void on_pushButtonResetCmd4_clicked();  // Capture d'écran
    void on_pushButtonResetCmd5_clicked();  // Photo par webcam
    // Onglet "Plus"
    void on_pushButtonOfficialWebsite_clicked();
    void on_listWidgetHelpers_doubleClicked(const QModelIndex &index);
    void on_listWidgetHelpers_entered(const QModelIndex &index);

private:
    Ui::MainWindow *ui;
    QSettings *settings;
    std::map<std::string, std::string> helpers;
#ifndef _WIN32
    QStringList cmd_screenshot_choices, cmd_webcamshot_choices;
    void loadPredefinedCmd();
    int updateCron(unsigned int new_time_limit);
#endif
    void loadConfiguration();
    void open_url_tester_contributor(const QModelIndex &index);
};

#endif // MAINWINDOW_H
