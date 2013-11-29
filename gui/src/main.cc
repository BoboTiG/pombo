
/*!
 * \file main.cc
 * \brief Start of Pombo GUI.
 * \author BoboTiG
 * \date 2013.06.25
 *
 * Copyleft ((C)) 2013 BoboTiG
 */


#include "mainwindow.h"


int main(int argc, char *argv[]) {
    if ( argc > 1 ) {
        if ( QString(argv[1]) == "--version" ) {
            printf("Pombo GUI version %s\n", POMBOGUI_VERSION);
            printf("Qt version %s\n", QT_VERSION_STR);
            return 0;
        }
    }

    QApplication gandalf(argc, argv);
    QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));
    QTranslator translator;
    translator.load(QString("%1/l10n/%2.qm")
                    .arg(gandalf.applicationDirPath())
                    .arg(QLocale::system().name()));
    gandalf.installTranslator(&translator);

    MainWindow balrog;
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    gandalf.setStyle(new QCleanlooksStyle());
#endif
    balrog.init();
    balrog.show();
    return gandalf.exec();
}
