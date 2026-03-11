void RAMFUNC SniffIso14443a(uint8_t param) {
    LEDsoff();
    // param:
    // bit 0 - trigger from first card answer
    // bit 1 - trigger from first reader 7-bit request
    iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);

    // Allocate memory from BigBuf for some buffers
    // free all previous allocations first
    BigBuf_free();
    BigBuf_Clear_ext(false);
    set_tracing(true);

    // The command (reader -> tag) that we're receiving.
    uint8_t *receivedCmd = BigBuf_calloc(MAX_FRAME_SIZE);
    uint8_t *receivedCmdPar = BigBuf_calloc(MAX_PARITY_SIZE);

    // The response (tag -> reader) that we're receiving.
    uint8_t *receivedResp = BigBuf_calloc(MAX_FRAME_SIZE);
    uint8_t *receivedRespPar = BigBuf_calloc(MAX_PARITY_SIZE);

    uint8_t previous_data = 0;
    int maxDataLen = 0, dataLen;
    bool TagIsActive = false;
    bool ReaderIsActive = false;

    // Set up the demodulator for tag -> reader responses.
    Demod14aInit(receivedResp, MAX_FRAME_SIZE, receivedRespPar);

    // Set up the demodulator for the reader -> tag commands
    Uart14aInit(receivedCmd, MAX_FRAME_SIZE, receivedCmdPar);

    if (g_dbglevel >= DBG_INFO) {
        DbpString("Press " _GREEN_("pm3 button") " to abort sniffing");
    }

    // The DMA buffer, used to stream samples from the FPGA
    dmabuf8_t *dma = get_dma8();
    uint8_t *data = dma->buf;

    // Setup and start DMA.
    if (FpgaSetupSscDma((uint8_t *) dma->buf, DMA_BUFFER_SIZE) == false) {
        if (g_dbglevel > DBG_ERROR) Dbprintf("FpgaSetupSscDma failed. Exiting");
        return;
    }

    // We won't start recording the frames that we acquire until we trigger;
    // a good trigger condition to get started is probably when we see a
    // response from the tag.
    // triggered == false -- to wait first for card
    bool triggered = !(param & 0x03);

    uint32_t rx_samples = 0;

    uint16_t checker = 12000;

    // loop and listen
    while (BUTTON_PRESS() == false) {
        WDT_HIT();
        LED_A_ON();

        if (checker-- == 0) {
            if (data_available()) {
                break;
            }
            checker = 12000;
        }

        register int readBufDataP = data - dma->buf;
        register int dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
        if (readBufDataP <= dmaBufDataP) {
            dataLen = dmaBufDataP - readBufDataP;
        } else {
            dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP;
        }

        // test for length of buffer
        if (dataLen > maxDataLen) {
            maxDataLen = dataLen;
            if (dataLen > (9 * DMA_BUFFER_SIZE / 10)) {
                Dbprintf("[!] blew circular buffer! | datalen %u", dataLen);
                break;
            }
        }
        if (dataLen < 1) {
            continue;
        }

        // primary buffer was stopped( <-- we lost data!
        if (AT91C_BASE_PDC_SSC->PDC_RCR == 0) {
            AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dma->buf;
            AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
            Dbprintf("[-] RxEmpty ERROR | data length %d", dataLen); // temporary
        }
        // secondary buffer sets as primary, secondary buffer was stopped
        if (AT91C_BASE_PDC_SSC->PDC_RNCR == 0) {
            AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dma->buf;
            AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
        }

        LED_A_OFF();

        // Need two samples to feed Miller and Manchester-Decoder
        if (rx_samples & 0x01) {

            // no need to try decoding reader data if the tag is sending
            if (TagIsActive == false) {

                uint8_t readerdata = (previous_data & 0xF0) | (*data >> 4);

                if (MillerDecoding(readerdata, (rx_samples - 1) * 4)) {
                    LED_C_ON();

                    // check - if there is a short 7bit request from reader
                    if ((!triggered) && (param & 0x02) && (Uart.len == 1) && (Uart.bitCount == 7)) {
                        triggered = true;
                    }

                    if (triggered) {
                        if (!LogTrace(receivedCmd,
                                      Uart.len,
                                      Uart.startTime * 16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
                                      Uart.endTime * 16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
                                      Uart.parity,
                                      true)) {
                            break;
                        }
                    }
                    // ready to receive another command
                    Uart14aReset();
                    // reset the demod code, which might have been
                    // false-triggered by the commands from the reader
                    Demod14aReset();
                    LED_B_OFF();
                }
                ReaderIsActive = (Uart.state != STATE_14A_UNSYNCD);
            }

            // no need to try decoding tag data if the reader is sending - and we cannot afford the time
            if (ReaderIsActive == false) {

                uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);

                if (ManchesterDecoding(tagdata, 0, (rx_samples - 1) * 4)) {

                    LED_B_ON();

                    if (!LogTrace(receivedResp,
                                  Demod.len,
                                  Demod.startTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                                  Demod.endTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                                  Demod.parity,
                                  false)) break;

                    if ((!triggered) && (param & 0x01)) {
                        triggered = true;
                    }

                    // ready to receive another response.
                    Demod14aReset();
                    // reset the Miller decoder including its (now outdated) input buffer
                    Uart14aReset();
                    //Uart14aInit(receivedCmd, MAX_FRAME_SIZE, receivedCmdPar);
                    LED_C_OFF();
                }
                TagIsActive = (Demod.state != DEMOD_14A_UNSYNCD);
            }
        }

        previous_data = *data;
        rx_samples++;
        data++;
        if (data == dma->buf + DMA_BUFFER_SIZE) {
            data = dma->buf;
        }
    } // end main loop

    FpgaDisableTracing();

    if (g_dbglevel >= DBG_ERROR) {
        Dbprintf("trace len = " _YELLOW_("%d"), BigBuf_get_traceLen());
    }
    switch_off();
}
