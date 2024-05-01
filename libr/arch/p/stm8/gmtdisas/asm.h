
typedef enum {
  AREA_NONE,
  SRAM,
  EEPROM,
  OPT,
  FLASH,
  BOOT_ROM,
  GPIO
} areas;

typedef struct {
  uint16_t add;
  char name[32];
} ioreg;

//void Write_Eeprom_Data (FILE *file, datablock *block);
//void Write_Opt_Data (FILE *file, datablock *block);
