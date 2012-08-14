/* QWQNG_Linux Library

  Copyright (c) 2012, The Quantum World Corporation.
  All rights reserved.
  
  New BSD License

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
      * Redistributions of source code must retain the above copyright
	notice, this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
	notice, this list of conditions and the following disclaimer in the
	documentation and/or other materials provided with the distribution.
      * Neither the name of the <organization> nor the
	names of its contributors may be used to endorse or promote products
	derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef __qwqng_hpp__
#define __qwqng_hpp__


#define FTDIDEVICE_ID_PREFIX_               "QWR"
#define FTDIDEVICE_ID_DEVELOPMENT_          "D"
#define FTDIDEVICE_TX_TIMEOUT_MILLIS_       5000
#define FTDIDEVICE_READ_FRAME_SIZE_         1024
#define FTDIDEVICE_START_COMMAND_           0x96
#define FTDIDEVICE_STOP_COMMAND_            0xE0
#define FTDIDEVICE_READ_SERIAL_COMMAND_     0x60

#define FTDIDEVICE_TEST_STATUS_COMMAND_     0xB0
#define FTDIDEVICE_TEST_FINAL_BASE_         0xA0
#define FTDIDEVICE_TEST_CHANNELS_BASE_      0x70
#define FTDIDEVICE_TEST_CLEAR_STATS_FLAG_   0xC0

#define FTDIDEVICE_RNG_OUTPUT_ENABLED_MASK_ 0X0001
#define FTDIDEVICE_USB_STREAMING_MASK_ 	    0X0002
#define FTDIDEVICE_TEST_BAD_STATS_MASK_     0x0004
#define FTDIDEVICE_CLIENT_CONNECTED_MASK_   0X0008

#define FTDIDEVICE_MAX_ARRAY_SIZE_          8192

#define FTDIDEVICE_HALF_OF_UNIFORM_LSB_     1.7763568394002505e-15
#define FTDIDEVICE_2_PI_                    6.283185307179586

// Custom QNG Status messages
//
// MessageId:   QNG_S_OK
// MessageText: QNG device reports success.
//
#define QNG_S_OK			0x00044400L

//
// MessageId:   QNG_E_GENERAL_FAILURE
// MessageText: QNG general error.
//
#define QNG_E_GENERAL_FAILURE		0x80044401L

//
// MessageId:   QNG_E_IO_ERROR
// MessageText: QNG I/O error.
//
#define QNG_E_IO_ERROR			0x80044402L

//
// MessageId:   QNG_E_IO_TIMEOUT
// MessageText: QNG I/O request has timed out.
//
#define QNG_E_IO_TIMEOUT		0x80044403L

//
// MessageId:   QNG_E_IO_ARRAY_OVERSIZED
// MessageText: QNG read array size exceeds max size.
//
#define QNG_E_IO_ARRAY_OVERSIZED	0x80044404L

//
// MessageId:   QNG_E_STATS_EXCEPTION
// MessageText: QNG test statistics exception.
//
#define QNG_E_STATS_EXCEPTION   	0x80044406L

//
// MessageId:   QNG_E_STATS_UNSUPPORTED
// MessageText: QNG stats not supported this device.
//
#define QNG_E_STATS_UNSUPPORTED   	0x80044407L

//
// MessageId:   QNG_E_DEVICE_NOT_OPENED
// MessageText: QNG device not found or already in use.
//
#define QNG_E_DEVICE_NOT_OPENED		0x8004440AL

//
// MessageId:   S_OK
// MessageText: No error occurred.
//
#define S_OK				0x00000000L



#include "stdint.h"
#include <sys/types.h>
#include <unistd.h> 
#include <vector>
#include <math.h>
#include <string>
#include <string.h>
#include <ftdi.h>

/* Forward Declaration */
class FtdiDevice;
class IDevice;
class QngStatus;


class QWQNG {  
public:
  
  /* Construct Indirectly */
  static QWQNG* Instance();  
  
  /* Public Destructor */
  ~QWQNG();
  
   
protected:
  
  /* Pointer to Class IDevice */
  IDevice* pDevice;	
  
     
public:
  
  /* Properties */
  char* statusString_;	
  char* devId_;		
  
  /* Device Manipulators */
  char* StatusString(); 
  char* DeviceID();   
  int RandInt32(long* pVal);
  int RandUniform(double* pVal);
  int RandNormal(double *pVal);
  int RandBytes(char* pval, long length);
  int Clear(); 
  int Reset();
  int RuntimeInfo(float* pVal);
  
private:
  
  /* Private Constructor */
  QWQNG();
  
  /* Copy constructor is private */
  QWQNG(QWQNG const&){};
  
  /* Assignment operator is private */
  QWQNG& operator=(QWQNG const&){};
  
  /* Instance private constructor variable */
  static QWQNG* _instance;	
  
};


class IDevice {
private:
    /* property */
    std::string deviceId_;

public:
    /* Functions */
    virtual void Open() = 0;
    virtual void Close() = 0;
    virtual void Clear() = 0;
    virtual void Reset() = 0;

    virtual void GetBytes(char* bytes, int bytesRequested) = 0;
    virtual void GetInt32(int32_t* int32) = 0;
    virtual void GetUniform(double* uniform) = 0;
    virtual void GetNormal(double* normal) = 0;

    virtual void GetRuntimeInfo(float* testData) = 0;

    virtual std::string& GetDeviceId() {
        return deviceId_;
    }

    virtual void SetDeviceId(std::string deviceId) {
        deviceId_ = deviceId;
    }
};


class FtdiDevice : IDevice {
  
private:
  
    /* Main context structure for all libftdi functions */
    struct ftdi_context ftdic; 			
    
    /* Structure for Finding Multiple FTDI Devices */
    struct QNGdev {
      struct ftdi_device_list *devlist, *curdev;
      int VID;
      int PID;
    };  
    struct QNGdev Buffer[2]; // Init QNGdev Structure 

    /* Structure for Connected FTDI Devices' Parameters ( Initialize in FindOpen() ) */
    struct QNGparam {
      char manufacturer[128], description[128], serialnumber[9];
    };
    
    /* Properties */
    char serialInfo[9];
    char descInfo[128];
    char manuInfo[128];
    int devPID;
    int devVID;   
    int txchunksize;
    int rxchunksize; 
    int ftdiStatus;		     
    unsigned char internalSerialNum_[6];
    bool haveNormU1_;
    double normU1_;
    double normalConjugate_;  

public:
  
    /* Constructor, Destructor */
    FtdiDevice();
    ~FtdiDevice();

    /* Functions */
    virtual void Open();
    virtual void Close();
    virtual void Clear();
    virtual void Reset();
    virtual void GetBytes(char* bytes, int bytesRequested);
    virtual void GetInt32(int32_t* int32);
    virtual void GetUniform(double* uniform);
    virtual void GetNormal(double* normal);
    virtual void GetRuntimeInfo(float* runtimeInfo);
    
private:
    
    /* Functions */
    void FtdiClose();
    void FindOpen();
    void Initialize();
    void FtdiRead(void* receiveBuffer, int bytesRequested);
    void FtdiUncheckedRead(void* receiveBuffer, int bytesRequested);
    void FtdiWrite(void* transmitBuffer, int bytesToTransmit);
    void FtdiSendCommand(unsigned char command);
    void FtdiClearReceiveBuffer();
    void FtdiClearBuffers();
    void CheckTestStatsStatus();
    double Uint48ToUniform(uint64_t uint48);
    float CalcEntropy(double p);
    
};


class QngStatus {
public:
  
    /* Construct Indirectly */
    static QngStatus& Instance();
    
    /* Functions */
    long GetStatus();
    std::string& GetStatusString();
    long SetStatus(long newStatus);

private:
  
    /* Private Constructor */
    QngStatus();
    
    /* Copy constructor is private */
    QngStatus(QngStatus const&) {};
    
    /* Assignment operator is private */
    QngStatus& operator=(QngStatus const&) {};
    
    /* Private Destructor */
    ~QngStatus();

private:  
  
    /* properties */
    long status_;
    std::string statusString_;
    
};

#endif


