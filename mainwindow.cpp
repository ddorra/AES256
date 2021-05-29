#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <qaesencryption.h>
#include <QCryptographicHash>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

}

MainWindow::~MainWindow()
{
    delete ui;
}

QByteArray MainWindow::HashKey(QString key)
{
    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    return hashKey;
}
QByteArray MainWindow::HashIV(QString iv)
{
    QByteArray hashIV = QCryptographicHash::hash(iv.toLocal8Bit(), QCryptographicHash::Md5);
    return hashIV;
}
void MainWindow::on_EncryptButton_clicked()
{
    AES_Encryption encryption(AES_Encryption::ISO);

    //Ключ, на основании которого строятся раундовые ключи
    QString key=ui->Key->text();
    //Двоичный вектор инициализации,
    //используется для предотвращения повторения шифрования данных, произвольное число
    QString iv=ui->IV->text();

    QString encryptedMes=ui->encrypt->text();

    QByteArray encodeText = encryption.Encode(encryptedMes.toLocal8Bit(), HashKey(key), HashIV(iv));
    QByteArray decodeText = encryption.Decode(encodeText, HashKey(key), HashIV(iv));

    QString decodedString = QString(encryption.removePadding(decodeText));

    ui->EencrypedMess->setText(encodeText);
    ui->DecryptedMess->setText(decodedString);

}

void MainWindow::on_DecryptButton_clicked()
{
    AES_Encryption encryption(AES_Encryption::ISO);

    //Ключ, на основании которого строятся раундовые ключи
    QString key=ui->Key->text();

    //Двоичный вектор инициализации,
    //используется для предотвращения повторения шифрования данных, произвольное число
    QString iv=ui->IV->text();

    //Дешифруемое сообщение
    QString DecryptedMes=ui->Decrypt->text();
    QByteArray decodeText = encryption.Decode(DecryptedMes.toLocal8Bit(), HashKey(key), HashIV(iv));

    QString decodedString = QString(encryption.removePadding(decodeText));

    ui->encrypt->setText(decodedString);
    ui->DecryptedMess->setText(decodedString);
}

