#include "qaesencryption.h"
#include <QDebug>
#include <QVector>

QByteArray AES_Encryption::Crypt(const QByteArray &rawText, const QByteArray &key, const QByteArray &iv, AES_Encryption::Padding padding)
{
    return AES_Encryption(padding).Encode(rawText, key, iv);
}

QByteArray AES_Encryption::Decrypt( const QByteArray &rawText, const QByteArray &key, const QByteArray &iv, AES_Encryption::Padding padding)
{
     return AES_Encryption(padding).Decode(rawText, key, iv);
}

QByteArray AES_Encryption::keyExpansion(const QByteArray &key)
{
     return AES_Encryption().KeyExpansion(key);
}

//Снятие дополнения
QByteArray AES_Encryption::RemovePadding(const QByteArray &Text, AES_Encryption::Padding padding)
{
    if (Text.isEmpty())
        return Text;

    QByteArray ModText(Text);
    switch (padding)
    {
    case Padding::ISO:
    {
         // Поиск последнего байта не равного нулю
         int marker_index = ModText.length() - 1;
         for (; marker_index >= 0; --marker_index)
         {
                if (ModText.at(marker_index) != 0x00)
                {
                  break;
                }
         }
        // Проверка на байт маркировки
        if (ModText.at(marker_index) == '\x80')
        {
            ModText.truncate(marker_index);
        }
        break;
    }
    }
    return ModText;
}

namespace
{
    quint8 xTime(quint8 x)
    {
        return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
    }

    quint8 multiply(quint8 x, quint8 y)
    {
        return (((y & 1) * x) ^ ((y>>1 & 1) * xTime(x)) ^ ((y>>2 & 1) * xTime(xTime(x))) ^ ((y>>3 & 1)
                * xTime(xTime(xTime(x)))) ^ ((y>>4 & 1) * xTime(xTime(xTime(xTime(x))))));
    }
}

AES_Encryption::AES_Encryption(Padding padding)
    : m_nb(4), m_blocklen(16), m_padding(padding)
    , m_state(nullptr)
{
    int nk = 8;
    int keylen = 32;
    int nr = 14;
    int expandedKey = 240;
        m_nk = nk;
        m_keyLen = keylen;
        m_nr = nr;
        m_expandedKey =expandedKey;
}
QByteArray AES_Encryption::getPadding(int currSize, int alignment)
{
    int size = (alignment - currSize % alignment) % alignment;
    switch(m_padding)
    {
    case Padding::ISO:
        if (size > 0)
            return QByteArray (size - 1, 0x00).prepend('\x80');
        break;
    }
    return QByteArray();
}

//Формирует набор раундовых ключей
//длинную таблицу, состоящую из Nb*(Nr + 1) столбцов
//или (Nr + 1) блоков, каждый из которых равен по размеру State.
//Первый раундовый ключ заполняется
//на основе секретного ключа преобразованное по формуле
//KeySchedule[r][c] = SecretKey[r + 4c], r = 0,1...4; c = 0,1..Nk.
QByteArray AES_Encryption::KeyExpansion(const QByteArray &key)
{
  {
      int i, k;
      quint8 temp[4];
      QByteArray roundKey(key); // Ключ превого раунда (исходный)

      // Все остальные  ключи найдены из предыдущих ключей
      for(i = m_nk; i < m_nb * (m_nr + 1); i++)
      {
        temp[0] = (quint8) roundKey.at((i-1) * 4 + 0);
        temp[1] = (quint8) roundKey.at((i-1) * 4 + 1);
        temp[2] = (quint8) roundKey.at((i-1) * 4 + 2);
        temp[3] = (quint8) roundKey.at((i-1) * 4 + 3);

        if (i % m_nk == 0)
        {
            // Сдвиг четырех байтов влево
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);

            temp[0] =  temp[0] ^ rcon[i/m_nk];
        }

        if (i % m_nk == 4)
        {
            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);
        }
        roundKey.insert(i * 4 + 0, (quint8) roundKey.at((i - m_nk) * 4 + 0) ^ temp[0]);
        roundKey.insert(i * 4 + 1, (quint8) roundKey.at((i - m_nk) * 4 + 1) ^ temp[1]);
        roundKey.insert(i * 4 + 2, (quint8) roundKey.at((i - m_nk) * 4 + 2) ^ temp[2]);
        roundKey.insert(i * 4 + 3, (quint8) roundKey.at((i - m_nk) * 4 + 3) ^ temp[3]);
      }
      return roundKey;
  }
}

// добавление RoundKey в State функцией XOR
void AES_Encryption::addRoundKey(const quint8 round, const QByteArray &expKey)
{
  QByteArray::iterator iterator = m_state->begin();
  for(int i=0; i < 16; ++i)
  {
      iterator[i] = (quint8) iterator[i] ^ (quint8) expKey.at(round * m_nb * 4 + (i/4) * m_nb + (i%4));
  }
}

// Заменяет значения в матрице State значениями в S-box
void AES_Encryption::sub_Bytes()
{
  QByteArray::iterator iterator = m_state->begin();
  for(int i = 0; i < 16; i++)
  {
    iterator[i] = getSBoxValue((quint8) iterator[i]);
  }
}

// Функция ShiftRow() сдвигает строки в state влево
// Циклический сдвиг влево на 1 элемент для первой строки, на 2 для второй и на 3 для третьей. Нулевая строка не сдвигается.
void AES_Encryption::shiftRows()
{
    QByteArray::iterator iterator = m_state->begin();
    quint8 temp;

    temp   = (quint8)iterator[1];
    iterator[1]  = (quint8)iterator[5];
    iterator[5]  = (quint8)iterator[9];
    iterator[9]  = (quint8)iterator[13];
    iterator[13] = (quint8)temp;

    temp   = (quint8)iterator[2];
    iterator[2]  = (quint8)iterator[10];
    iterator[10] = (quint8)temp;
    temp   = (quint8)iterator[6];
    iterator[6]  = (quint8)iterator[14];
    iterator[14] = (quint8)temp;

    temp   = (quint8)iterator[3];
    iterator[3]  = (quint8)iterator[15];
    iterator[15] = (quint8)iterator[11];
    iterator[11] = (quint8)iterator[7];
    iterator[7]  = (quint8)temp;
}

// Смешивание столбцов матрицы
//каждая колонка в State представляется в виде многочлена
//и перемножается в поле GF(2^8) с фиксированным многочленом
void AES_Encryption::mixColumns()
{
  QByteArray::iterator iterator = m_state->begin();
  quint8 tmp, tm, t;

  for(int i = 0; i < 16; i += 4){
    t       = (quint8)iterator[i];
    tmp     =  (quint8)iterator[i] ^ (quint8)iterator[i+1] ^ (quint8)iterator[i+2] ^ (quint8)iterator[i+3] ;

    tm      = xTime( (quint8)iterator[i] ^ (quint8)iterator[i+1] );
    iterator[i]   = (quint8)iterator[i] ^ (quint8)tm ^ (quint8)tmp;

    tm      = xTime( (quint8)iterator[i+1] ^ (quint8)iterator[i+2]);
    iterator[i+1] = (quint8)iterator[i+1] ^ (quint8)tm ^ (quint8)tmp;

    tm      = xTime( (quint8)iterator[i+2] ^ (quint8)iterator[i+3]);
    iterator[i+2] =(quint8)iterator[i+2] ^ (quint8)tm ^ (quint8)tmp;

    tm      = xTime((quint8)iterator[i+3] ^ (quint8)t);
    iterator[i+3] =(quint8)iterator[i+3] ^ (quint8)tm ^ (quint8)tmp;
  }
}

// смешивает столбцы матрицы State.
//каждая колонка State перемножается с другим многочленом
//{0b}x3 + {0d}x2 + {09}x + {0e}.
void AES_Encryption::invMixColumns()
{
  QByteArray::iterator iterator = m_state->begin();
  quint8 a,b,c,d;
  for(int i = 0; i < 16; i+=4){
    a = (quint8) iterator[i];
    b = (quint8) iterator[i+1];
    c = (quint8) iterator[i+2];
    d = (quint8) iterator[i+3];

    iterator[i]   = (quint8) (multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09));
    iterator[i+1] = (quint8) (multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d));
    iterator[i+2] = (quint8) (multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b));
    iterator[i+3] = (quint8) (multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e));
  }
}

// Инверсные трансформации
// Замена значений в матрице State значениями в S-box.
// замены делаются из константной таблицы InvSbox
void AES_Encryption::invSubBytes()
{
    QByteArray::iterator iterator = m_state->begin();
    for(int i = 0; i < 16; ++i)
        iterator[i] = getSBoxInvert((quint8) iterator[i]);
}

void AES_Encryption::invShiftRows()
{
    QByteArray::iterator iterator = m_state->begin();
    uint8_t temp;

    temp   = (quint8)iterator[13];
    iterator[13] = (quint8)iterator[9];
    iterator[9]  = (quint8)iterator[5];
    iterator[5]  = (quint8)iterator[1];
    iterator[1]  = (quint8)temp;

    temp   = (quint8)iterator[10];
    iterator[10] = (quint8)iterator[2];
    iterator[2]  = (quint8)temp;
    temp   = (quint8)iterator[14];
    iterator[14] = (quint8)iterator[6];
    iterator[6]  = (quint8)temp;

    temp   = (quint8)iterator[7];
    iterator[7]  = (quint8)iterator[11];
    iterator[11] = (quint8)iterator[15];
    iterator[15] = (quint8)iterator[3];
    iterator[3]  = (quint8)temp;
}

QByteArray AES_Encryption::byteXor(const QByteArray &a, const QByteArray &b)
{
  QByteArray::const_iterator iterator1 = a.begin();
  QByteArray::const_iterator iterator2 = b.begin();
  QByteArray ModText;

  for(int i = 0; i < std::min(a.size(), b.size()); i++)
      ModText.insert(i,iterator1[i] ^ iterator2[i]);
  return ModText;
}

// Шифрование отркытого текста
QByteArray AES_Encryption::cipher(const QByteArray &expKey, const QByteArray &in)
{
  QByteArray output(in);
  m_state = &output;

  // Добавление ключа первого раунда
  addRoundKey(0, expKey);

  // Выполняются раунды
  for(quint8 round = 1; round < m_nr; ++round){
    sub_Bytes();
    shiftRows();
    mixColumns();
    addRoundKey(round, expKey);
  }

  // Последний раунд
  sub_Bytes();
  shiftRows();
  addRoundKey(m_nr, expKey);

  return output;
}

QByteArray AES_Encryption::invCipher(const QByteArray &expKey, const QByteArray &in)
{
    QByteArray output(in);
    m_state = &output;

    // Добавление ключа первого раунда
    addRoundKey(m_nr, expKey);

    // Выполняются раунды
    for(quint8 round=m_nr-1; round>0 ; round--){
        invShiftRows();
        invSubBytes();
        addRoundKey(round, expKey);
        invMixColumns();
    }

    // Последний раунд
    invShiftRows();
    invSubBytes();
    addRoundKey(0, expKey);

    return output;
}
// Зашифровка
QByteArray AES_Encryption::Encode(const QByteArray &rawText, const QByteArray &key, const QByteArray &iv)
{
    if (iv.isEmpty() || iv.size() != m_blocklen)
       return QByteArray();

    QByteArray expandedKey = KeyExpansion(key);
    QByteArray alignedText(rawText);

    // Заполнение массива padding
    alignedText.append(getPadding(rawText.size(), m_blocklen));
        QByteArray ret;
        QByteArray ivTemp(iv);
        for(int i=0; i < alignedText.size(); i+= m_blocklen) {
            alignedText.replace(i, m_blocklen, byteXor(alignedText.mid(i, m_blocklen),ivTemp));
            ret.append(cipher(expandedKey, alignedText.mid(i, m_blocklen)));
            ivTemp = ret.mid(i, m_blocklen);
        }
        return ret;
    return QByteArray();
}

QByteArray AES_Encryption::Decode(const QByteArray &rawText, const QByteArray &key, const QByteArray &iv)
{
    if (iv.isEmpty() || iv.size() != m_blocklen)
       return QByteArray();

    QByteArray ret;
    QByteArray expandedKey = KeyExpansion(key);


            QByteArray ivTemp(iv);
            for(int i=0; i < rawText.size(); i+= m_blocklen){
                ret.append(invCipher(expandedKey, rawText.mid(i, m_blocklen)));
                ret.replace(i, m_blocklen, byteXor(ret.mid(i, m_blocklen),ivTemp));
                ivTemp = rawText.mid(i, m_blocklen);
            }

    return ret;
}

QByteArray AES_Encryption::removePadding(const QByteArray &rawText)
{
    return RemovePadding(rawText, (Padding) m_padding);
}
