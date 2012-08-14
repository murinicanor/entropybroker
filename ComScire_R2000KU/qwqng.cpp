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

#include "qwqng.hpp"

/*************************************************** QWQNG Class *******************************************/

/* Class Initialization pointer */
QWQNG* QWQNG::_instance = 0;	


/* Private Constructor */
QWQNG* QWQNG::Instance() {
  
  _instance = new QWQNG();

  return _instance;
  
}


/* Private Constructor */
QWQNG::QWQNG() : pDevice(NULL) {
  // pDevice instance
  pDevice = (IDevice*)new FtdiDevice(); // create new instance
  
};
  
  
QWQNG::~QWQNG() {
  
  delete [] devId_;	  	// delallocate memory
  delete [] statusString_; 	// deallocate memory
  delete pDevice;		// release instance
  
};  


/* STATUS HANDLING: Property to return Status String */
char* QWQNG::StatusString() {
  
  // read status string
  std::string statusString = QngStatus::Instance().GetStatusString();
  statusString_ =  new char [statusString.size()];
  strcpy(statusString_, statusString.c_str());

  return statusString_;
  
}


/* Method to attempt to restart the hardware */
char* QWQNG::DeviceID() { 
  
  // read from device
  std::string deviceId = pDevice->GetDeviceId();
  devId_ =  new char [deviceId.size()];
  strcpy(devId_, deviceId.c_str());

  return devId_;

} 


/* Property to return a 32 bit random number */
int QWQNG::RandInt32(long* pVal) {  
  
  // read from device
  pDevice->GetInt32((int32_t*)pVal);  
  // Check status message
  if (QngStatus::Instance().GetStatus() == QNG_S_OK) 
      return S_OK;
  else 
    return QngStatus::Instance().GetStatus();
  
}


/* Property to return a uniform number [0,1) */
int QWQNG::RandUniform(double* pVal) { 
  
  // read from device
  pDevice->GetUniform(pVal);
  // Check status message
  if (QngStatus::Instance().GetStatus() == QNG_S_OK) 
      return S_OK;
  else 
    return QngStatus::Instance().GetStatus();
  
}


/* Property to return a normal number */
int QWQNG::RandNormal(double *pVal) { 
      
  // read from device
  pDevice->GetNormal(pVal);
  // Check status message
  if (QngStatus::Instance().GetStatus() == QNG_S_OK) 
      return S_OK;
  else 
    return QngStatus::Instance().GetStatus();
    
}


/* Property to read byte */
int QWQNG::RandBytes(char* pval, long length) { 
  
  // Check if valid length <= 8192
  if(length>8192) {
    QngStatus::Instance().SetStatus(QNG_E_IO_ARRAY_OVERSIZED);
    return QNG_E_IO_ARRAY_OVERSIZED;   
  }
  if(length==0)
    return S_OK;
  
  // read from device
  pDevice->GetBytes(pval, length);
  // Check status message
  if (QngStatus::Instance().GetStatus() == QNG_S_OK) 
      return S_OK;
  else 
    return QngStatus::Instance().GetStatus();
  
}


/* Method to clear all buffers */
  int QWQNG::Clear() { 
  
  // read from device
  pDevice->Clear();
  // Check status message
  if (QngStatus::Instance().GetStatus() == QNG_S_OK) 
      return S_OK;
  else 
    return QngStatus::Instance().GetStatus();

}   


/* Method to attempt to restart the hardware */
int QWQNG::Reset() { 
  
  // read from device
  pDevice->Reset();
  // Check status message
  if (QngStatus::Instance().GetStatus() == QNG_S_OK) 
      return S_OK;
  else 
    return QngStatus::Instance().GetStatus();

}


/* Property to return internal stats */
int QWQNG::RuntimeInfo(float* pVal) { 
  
  // read from device
  pDevice->GetRuntimeInfo(pVal);
  // Check status message
  if (QngStatus::Instance().GetStatus() == QNG_S_OK) 
      return S_OK;
  else 
    return QngStatus::Instance().GetStatus();
  
}   

/*************************************************** FtdiDevice Class *******************************************/

FtdiDevice::FtdiDevice() {
  
    QngStatus::Instance().SetStatus(QNG_E_DEVICE_NOT_OPENED);
    Open();
}


FtdiDevice::~FtdiDevice() { 
  
    Close(); 
}


// opens the next FTDI QNG device, if available
void FtdiDevice::Open() {  
  
    FindOpen(); // Finds QNG device, opens handle
      
    Initialize();  // Check internal stats, start RNG
    if (QngStatus::Instance().GetStatus() != QNG_S_OK) {
	Close();
	QngStatus::Instance().SetStatus(QNG_E_DEVICE_NOT_OPENED);
    }
    
}


void FtdiDevice::Close() {   
  
    // Stop Device
    FtdiSendCommand(FTDIDEVICE_STOP_COMMAND_);	
    FtdiClearReceiveBuffer();	// Clears the write buffer on the chip.
	    
    FtdiClose(); // close libftdi context
    QngStatus::Instance().SetStatus(QNG_E_DEVICE_NOT_OPENED);
    
}


void FtdiDevice::Clear() {  
  
    FtdiClearReceiveBuffer();	// Clears the write buffer on the chip.
    
}


void FtdiDevice::Reset() { 
  
    // Stop Device
    FtdiSendCommand(FTDIDEVICE_STOP_COMMAND_);
    FtdiClearReceiveBuffer();	// Clears the write buffer on the chip.
    
    // Reset Device
    if ((ftdiStatus = ftdi_usb_reset(&ftdic)) < 0 ) {
	//fprintf(stderr, "ftdi_usb_reset failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	return;
    }	
    
    // Open Device
    if ((ftdiStatus = ftdi_usb_open_desc(&ftdic, devVID, devPID, descInfo, serialInfo)) < 0 ) {
	//fprintf(stderr, "ftdi_usb_open_desc failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	return;
    } 
    
    // Set DeviceId for public use
    IDevice::SetDeviceId(serialInfo); 
    
    FtdiClearBuffers();	// clear RX/TX buffers on chip
    
    // Initialize Device
    Initialize();
    if (QngStatus::Instance().GetStatus() != QNG_S_OK) 
    {
	Close();
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	return;
    }  
      
}


void FtdiDevice::GetBytes(char* bytes, int bytesRequested) {

    if (bytesRequested>FTDIDEVICE_MAX_ARRAY_SIZE_ || bytesRequested<0)
    {
	QngStatus::Instance().SetStatus(QNG_E_IO_ARRAY_OVERSIZED);
	return;
    }
    FtdiRead(bytes, bytesRequested);
    
} 


void FtdiDevice::GetInt32(int32_t* int32) {
  
    FtdiRead(int32, 4);
    
}


void FtdiDevice::GetUniform(double* uniform) {
    
    uint64_t uint48 = 0;
    FtdiRead(&uint48, 6);

    *uniform = Uint48ToUniform(uint48);
    
}


void FtdiDevice::GetNormal(double* normal) {
    
    if (haveNormU1_ == true) {
	// create normU2
	uint64_t uint48 = 0;
	FtdiRead(&uint48, 6);
	double normU2 = Uint48ToUniform(uint48);
	normU2 += FTDIDEVICE_HALF_OF_UNIFORM_LSB_;

		// n1 = cos(2PI * u2) * sqrt(-2 * ln(u1)) 
		// n2 = sin(2PI * u2) * sqrt(-2 * ln(u1))
	double sqrtTerm = sqrt(-2.0 * log(normU1_));
	*normal = cos(FTDIDEVICE_2_PI_ * normU2) * sqrtTerm;
	normalConjugate_ = sin(FTDIDEVICE_2_PI_ * normU2) * sqrtTerm;

	haveNormU1_ = false;
    }
    else { // do not have uniform 1, fill conjugate;
	// create normU1
	uint64_t uint48 = 0;
	FtdiRead(&uint48, 6);
	normU1_ = Uint48ToUniform(uint48);
	normU1_ += FTDIDEVICE_HALF_OF_UNIFORM_LSB_;  

	haveNormU1_ = true;

	*normal = normalConjugate_;
    }
    
}


void FtdiDevice::GetRuntimeInfo(float* runtimeInfo) {
    
    // initialize to failure condition
    runtimeInfo[0] = 1.0;
    for (int i=0; i<=3; ++i) {
	runtimeInfo[4*i+1] = 0.0;
	runtimeInfo[4*i+2] = 0.0;
	runtimeInfo[4*i+3] = 0.0;
	runtimeInfo[4*i+4] = 1.0;
    }

    // Stop Device
    FtdiSendCommand(FTDIDEVICE_STOP_COMMAND_);

    // look for the internal serial number (this is used as a delimiter) - try this 4 times
    int attempt = 4;
    uint8_t serialNumCheck[6];
    while (attempt > 0) {
	FtdiClearReceiveBuffer();	// Clears the write buffer on the chip.
	FtdiSendCommand(FTDIDEVICE_READ_SERIAL_COMMAND_);
	FtdiUncheckedRead(serialNumCheck, 6);
	if (memcmp(serialNumCheck, internalSerialNum_, 6) == 0)
	    break;

	attempt--;
    }
    if (attempt <= 0)
	return;

    // get test stats status
    uint32_t rngStatus = 0;
    FtdiSendCommand(FTDIDEVICE_TEST_STATUS_COMMAND_);
    FtdiUncheckedRead(&rngStatus, 4);
    if (rngStatus & FTDIDEVICE_TEST_BAD_STATS_MASK_)
	runtimeInfo[0] = -1.0;
    else
	runtimeInfo[0] = 0.0;

    // request final out stats
    FtdiSendCommand(FTDIDEVICE_TEST_FINAL_BASE_ + 1);
    FtdiUncheckedRead(&runtimeInfo[3], 4);
    FtdiSendCommand(FTDIDEVICE_TEST_FINAL_BASE_ + 2);
    FtdiUncheckedRead(&runtimeInfo[4], 4);
    FtdiSendCommand(FTDIDEVICE_TEST_FINAL_BASE_ + 3);
    FtdiUncheckedRead(&runtimeInfo[2], 4);
    runtimeInfo[1] = CalcEntropy(runtimeInfo[2]);


    // request channel stats
    for (int j=0; j<3; j++) {
	FtdiSendCommand(FTDIDEVICE_TEST_CHANNELS_BASE_ + j*0x10 + 1);
	FtdiUncheckedRead(&runtimeInfo[j*4 + 4 + 3], 4);
	FtdiSendCommand(FTDIDEVICE_TEST_CHANNELS_BASE_ + j*0x10 + 2);
	FtdiUncheckedRead(&runtimeInfo[j*4 + 4 + 4], 4);
	FtdiSendCommand(FTDIDEVICE_TEST_CHANNELS_BASE_ + j*0x10 + 3);
	FtdiUncheckedRead(&runtimeInfo[j*4 + 4 + 2], 4);
	runtimeInfo[j*4 + 4 + 1] = CalcEntropy(runtimeInfo[j*4 + 4 + 2]);
    }

    // if request not due to bad stats, restart the device
    if ((rngStatus & FTDIDEVICE_TEST_BAD_STATS_MASK_) != FTDIDEVICE_TEST_BAD_STATS_MASK_) {
	FtdiSendCommand(FTDIDEVICE_START_COMMAND_);
    }
    
}


void FtdiDevice::FtdiClose() {
  
    // close libftdi USB device
    if( (ftdiStatus = ftdi_usb_close(&ftdic)) < 0 ) {
	  //fprintf(stderr, "ftdi_usb_close failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	  QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	  return;
    }	 
    // Free libftdi USB device lists
    ftdi_list_free(&Buffer[0].devlist);
    ftdi_list_free(&Buffer[1].devlist); 
    // deinitialize ftdi_context
    ftdi_deinit(&ftdic);

    QngStatus::Instance().SetStatus(QNG_E_DEVICE_NOT_OPENED);
    
}


void FtdiDevice::FindOpen() {
  
    QngStatus::Instance().SetStatus(QNG_S_OK);	// Set Status to OK
    
    int ret=0; 	// # of devices returned status
    int num_devs=0;	// number of FTDI devices found 
    int i=0;	// iterator for number of devices
    
    ftdiStatus = 0; // libftdi return value status
    
    // Set VID/PID Parameters for search
    Buffer[0].VID = 0x0403; // QNG Model R2000KU VendorID  (VID)
    Buffer[0].PID = 0x6001; // QNG Model R2000KU ProductID (PID)
    Buffer[1].VID = 0x0403; // Other QNG Device VID    
    Buffer[1].PID = 0x6014; // Other QNG Device PID
    
    // Initialize Main context structure for all libftdi functions
    if (ftdi_init(&ftdic) < 0) {
	//fprintf(stderr, "ftdi_init failed\n");
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	return;
    }
	
    // Find all connected QNG devices with PIDs 6001 and 6014
    for (int j=0; j<2; j++) {
      if ((ret = ftdi_usb_find_all(&ftdic, &Buffer[j].devlist, Buffer[j].VID, Buffer[j].PID)) < 0) {
	  //fprintf(stderr, "ftdi_usb_find_all failed: %d (%s)\n", ret, ftdi_get_error_string(&ftdic));
	  QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	  return;
      }
      num_devs = num_devs + ret;	// increment device count
    }
    
    if (num_devs == 0) {	// if no devices found, quit
	QngStatus::Instance().SetStatus(QNG_E_DEVICE_NOT_OPENED);
	return;
    }
	    
    struct QNGparam QNG[num_devs]; // Init QNGparam structure

    i = 0; // initialize iterator 
    
    // get devices' parameters
    for (int k=0; k<2; k++) {
      for (Buffer[k].curdev = Buffer[k].devlist; Buffer[k].curdev != NULL; i++) {
	  //printf("Checking device: %d\n", i+1);	// testing purposes
	  if ((ftdiStatus = ftdi_usb_get_strings(&ftdic, Buffer[k].curdev->dev, QNG[i].manufacturer, 128, QNG[i].description, 128, QNG[i].serialnumber, 9)) < 0) {
	      //fprintf(stderr, "ftdi_usb_get_strings failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	      QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	      return;
	  }
	  Buffer[k].curdev = Buffer[k].curdev->next;	// increment next device list
      }
    }
    
    // Open First available QNG Model R2000KU with  Prefix "QWR2"
    for (int j=0; j<num_devs; j++) {
      if (memcmp(QNG[j].serialnumber, "QWR2", 4) == 0) {
	if ((ftdiStatus = ftdi_usb_open_desc(&ftdic, Buffer[0].VID, Buffer[0].PID, QNG[j].description, QNG[j].serialnumber)) < 0 ) {
	  //fprintf(stderr, "ftdi_usb_open_desc failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	  QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	  return;
	}
	// Store opened device's parameters for internal use
	memcpy(manuInfo,QNG[j].manufacturer, 128);
	memcpy(serialInfo,QNG[j].serialnumber, 9);
	memcpy(descInfo,QNG[j].description, 128);
	devPID = Buffer[0].PID;
	devVID = Buffer[0].VID;
	// Set deviceId = Serial Number for Public Use
	IDevice::SetDeviceId(QNG[j].serialnumber);
	// Set internal buffer size for R2000KU
	txchunksize = 2*FTDIDEVICE_MAX_ARRAY_SIZE_;
	rxchunksize = 2*FTDIDEVICE_MAX_ARRAY_SIZE_;
	break;
      }
      else if (memcmp(QNG[j].serialnumber, "QWR3", 4) == 0) { // If no R2000KU found, open first available QNG Model R32MU with  Prefix "QWR3" 
	if ((ftdiStatus = ftdi_usb_open_desc(&ftdic, Buffer[1].VID, Buffer[1].PID, QNG[j].description, QNG[j].serialnumber)) < 0 ) {
	  //fprintf(stderr, "ftdi_usb_open_desc failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	  QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	  return;
	}
	// Store opened device's parameters  for internal use
	memcpy(manuInfo,QNG[j].manufacturer, 128);
	memcpy(serialInfo,QNG[j].serialnumber, 9);
	memcpy(descInfo,QNG[j].description, 128);
	devPID = Buffer[1].PID;
	devVID = Buffer[1].VID;
	// Set deviceId = Serial Number for Public Use
	IDevice::SetDeviceId(QNG[j].serialnumber);
	// Set internal buffer size for R32MU
	txchunksize = 32*FTDIDEVICE_MAX_ARRAY_SIZE_;
	rxchunksize = 32*FTDIDEVICE_MAX_ARRAY_SIZE_;
	break;
      }
      QngStatus::Instance().SetStatus(QNG_E_DEVICE_NOT_OPENED);	// Set Status Device Not Opened
    }
    
}


// initialize QNG device
void FtdiDevice::Initialize() {    
  
    // configure rx/tx buffer chunk size
    if (ftdi_write_data_set_chunksize(&ftdic, txchunksize) < 0 ||
	ftdi_read_data_set_chunksize(&ftdic, rxchunksize) < 0) {
	//fprintf(stderr,"Can't set chunksize: %s\n",ftdi_get_error_string(&ftdic));
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	return;
    }
   

    /*************	FTDI chip keeps data in internal buffer for a specific amount of time if buffer is not full yet ************/
    // Set latency timer = 2ms
    if ((ftdiStatus = ftdi_set_latency_timer(&ftdic, 0x2)) < 0 ) {
	//fprintf(stderr, "ftdi_set_latency_timer failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	return;
    } 
   
    /************************ Set Baud Rate Only for Bitbang Mode. Does not apply to our devices ***********************************	
    // Set Baud Rate
    if ((ftdiStatus = ftdi_set_baudrate(&ftdic, 1500000)) < 0 ) {	// 262,144 Baud /4 (65536) r2000ku, 4,194,304 Baud /4 (1048576) r32mu
	//fprintf(stderr, "ftdi_set_baudrate failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	return;
    } 
*/	
    FtdiSendCommand(FTDIDEVICE_STOP_COMMAND_); // stop device	
    FtdiClearReceiveBuffer();
    unsigned char serialNumCheck[6];
    serialNumCheck[1] = 0;
    int attempt = 5;
    while (attempt > 0) {	    
	// Clears the write buffer on the chip.
	if ((ftdiStatus = ftdi_usb_purge_tx_buffer(&ftdic)) < 0 ) {
	  //fprintf(stderr, "ftdi_usb_purge_tx_buffer failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	  QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
	  return;
	}
	FtdiSendCommand(FTDIDEVICE_READ_SERIAL_COMMAND_);	// Send Read Delimiter Command
	internalSerialNum_[1] = serialNumCheck[1] + 1;
	FtdiUncheckedRead(internalSerialNum_, 6);
	if (memcmp(serialNumCheck, internalSerialNum_, 6) == 0)
	    break;

	memcpy(serialNumCheck, internalSerialNum_, 6);

	attempt--;
    }
    if (attempt <= 0) {
	QngStatus::Instance().SetStatus(QNG_E_DEVICE_NOT_OPENED);
	return;
    } 

    // write out start word to physically start device
    FtdiSendCommand(FTDIDEVICE_START_COMMAND_);
    FtdiSendCommand(FTDIDEVICE_TEST_CLEAR_STATS_FLAG_); // clear internal Bad Stats flag
    usleep(10*1000);

    // first 4-5 bits produced from device are invalid (always zero); discard first byte
    uint8_t discardByte;
    FtdiRead(&discardByte, 1);
    // fill normU1, so immediate calls to GetNormal will be correct
    uint64_t uint48 = 0;
    FtdiRead(&uint48, 6);
    normU1_ = Uint48ToUniform(uint48);
    normU1_ += FTDIDEVICE_HALF_OF_UNIFORM_LSB_;
    haveNormU1_ = true; 
    
}


void FtdiDevice::FtdiRead(void* receiveBuffer, int bytesRequested) {
  
    QngStatus::Instance().SetStatus(QNG_S_OK);	// Set Status to OK
    
    // Read random bytes Requested. Bytes are stored as unsigned character
    ftdiStatus = ftdi_read_data(&ftdic, (unsigned char*)receiveBuffer, bytesRequested);	  
    if (ftdiStatus < 0) {
	//fprintf(stderr, "ftdi_read_data failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
    }
    else if (ftdiStatus != bytesRequested) {
	QngStatus::Instance().SetStatus(QNG_E_IO_TIMEOUT);
	CheckTestStatsStatus();
    }  
    
}


// use FtdiRead, this read does not check test status on failure
// only the test status function uses this to prevent an infinite callback loop
void FtdiDevice::FtdiUncheckedRead(void* receiveBuffer, int bytesRequested) {
  
    QngStatus::Instance().SetStatus(QNG_S_OK);	// Set Status to OK
    
    // Read random bytes Requested. Bytes are stored as unsigned character
    ftdiStatus = ftdi_read_data(&ftdic, (unsigned char*)receiveBuffer, bytesRequested);	  
    if (ftdiStatus < 0) {
	//fprintf(stderr, "ftdi_read_data failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
    }
    else if (ftdiStatus != bytesRequested) {
	QngStatus::Instance().SetStatus(QNG_E_IO_TIMEOUT); 
    }
    
}


void FtdiDevice::FtdiWrite(void* transmitBuffer, int bytesToTransmit) {
  
    QngStatus::Instance().SetStatus(QNG_S_OK);	// Set Status to OK
    // Send Data to Device
    ftdiStatus = ftdi_write_data(&ftdic, (unsigned char*)transmitBuffer, bytesToTransmit);  
    if (ftdiStatus < 0) {
	//fprintf(stderr, "ftdi_write_data failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
	QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
    }
    else if (ftdiStatus != bytesToTransmit) {
	QngStatus::Instance().SetStatus(QNG_E_IO_TIMEOUT);
    }
    
}


void FtdiDevice::FtdiSendCommand(unsigned char command) { 
  
    FtdiWrite(&command, 1);
    
}


void FtdiDevice::FtdiClearReceiveBuffer() {
  
    // Clears the write buffer on the chip.
    if ((ftdiStatus = ftdi_usb_purge_tx_buffer(&ftdic)) < 0 ) {
      //fprintf(stderr, "ftdi_usb_purge_tx_buffer failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
      QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
      return;
    }
    // read data in queue
    unsigned char* purgeBuffer = new unsigned char[txchunksize];
    FtdiUncheckedRead(purgeBuffer, txchunksize);
    delete [] purgeBuffer;
    
}


void FtdiDevice::FtdiClearBuffers() {
  
    // Purge RX/TX Buffers on the chip
    if ((ftdiStatus = ftdi_usb_purge_buffers(&ftdic)) < 0 ) {
      //fprintf(stderr, "ftdi_usb_purge_buffers failed: %d (%s)\n", ftdiStatus, ftdi_get_error_string(&ftdic));
      QngStatus::Instance().SetStatus(QNG_E_IO_ERROR);
      return;
    }
    // read data in queue
    unsigned char* purgeBuffer = new unsigned char[txchunksize];
    FtdiUncheckedRead(purgeBuffer, txchunksize);
    delete [] purgeBuffer;
    
}


void FtdiDevice::CheckTestStatsStatus() {
    // Stop Device
    FtdiSendCommand(FTDIDEVICE_STOP_COMMAND_);
    
    // look for the internal serial number (this is used as a delimiter) - try this 4 times
    int attempt = 4;
    unsigned char serialNumCheck[6];
    while (attempt > 0) {
	FtdiClearReceiveBuffer();	// Clears the write buffer on the chip.
	FtdiSendCommand(FTDIDEVICE_READ_SERIAL_COMMAND_);	// Send Read Delimiter Command
	FtdiUncheckedRead(serialNumCheck, 6);
	if (memcmp(serialNumCheck, internalSerialNum_, 6) == 0)
	    break;

	attempt--;
    }
    if (attempt <= 0) {
	return;
    } 

    // get test stats status
    uint32_t rngStatus = 0;
    FtdiSendCommand(FTDIDEVICE_TEST_STATUS_COMMAND_);
    FtdiUncheckedRead(&rngStatus, 4);
    if (rngStatus & FTDIDEVICE_TEST_BAD_STATS_MASK_)
	QngStatus::Instance().SetStatus(QNG_E_STATS_EXCEPTION);
    
}


double FtdiDevice::Uint48ToUniform(uint64_t uint48) {
  
	// copy 6 bytes into mantissa
	double uniform = (double)uint48;
	uniform /= 281474976710656.0;  // 2^(6*8)

	return uniform;
	
}


float FtdiDevice::CalcEntropy(double p) {
  
    return (float)(-(p*log(p) + (1.0-p)*log(1.0-p)) / log(2.0));
    
}
    

/*************************************************** QngStatus Class *******************************************/

/* Instance */
QngStatus& QngStatus::Instance() {
    static QngStatus instance;
    return instance;
}


/* Constructor */
QngStatus::QngStatus()
    : status_(QNG_E_DEVICE_NOT_OPENED)
    , statusString_("QNG device not found or already in use.")
{ }


/* Destructor */
QngStatus::~QngStatus() { }



long QngStatus::GetStatus() {
    return status_;
}


std::string& QngStatus::GetStatusString() {
    return statusString_;
}


long QngStatus::SetStatus(long newStatus) {
    if (status_ != QNG_S_OK) {
	if ((newStatus != QNG_S_OK) && (newStatus != QNG_E_STATS_EXCEPTION) && (newStatus != QNG_E_DEVICE_NOT_OPENED))
	    return status_;
    }
    status_ = newStatus;
    
    switch (status_) {
	case QNG_S_OK:
	    statusString_ = "QNG device reports success.";
	    break;
	case QNG_E_GENERAL_FAILURE:
	    statusString_ = "QNG general error.";
	    break;
	case QNG_E_IO_ERROR:
	    statusString_ = "QNG I/O error.";
	    break;
	case QNG_E_IO_TIMEOUT:
	    statusString_ = "QNG I/O request has timed out.";
	    break;
	case QNG_E_IO_ARRAY_OVERSIZED:
	    statusString_ = "QNG read array size exceeds max size.";
	    break;
	case QNG_E_DEVICE_NOT_OPENED:
	    statusString_ = "QNG device not found or already in use.";
	    break;
	case QNG_E_STATS_EXCEPTION:
	    statusString_ = "QNG test statistics exception.";
	    break;
	case QNG_E_STATS_UNSUPPORTED:
	    statusString_ = "QNG stats not supported with this device.";
	    break;
	default:
	    status_ = QNG_E_GENERAL_FAILURE;
	    statusString_ = "QNG general error.";
    }

    return status_;
}


