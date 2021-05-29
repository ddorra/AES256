#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    QByteArray HashKey(QString key);
    QByteArray HashIV(QString IV);
private slots:
    void on_EncryptButton_clicked();

    void on_DecryptButton_clicked();


private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
