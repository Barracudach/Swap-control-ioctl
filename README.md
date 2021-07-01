# Swap-control-ioctl
Хук функции DRIVER_DISPATCH(IRP_MJ_DEVICE_CONTROL) отвечающую за ввод-вывод ioctl устройства.
Суть такова, что мы в сам указатель PDRIVER_DISPATCH пишем адресс trampoline который находится в диапазоне
секции .text ,тем самым я подразумевал что мы можем пройти слепую проверку античита :
if (major_function.address < section.address || 
        major_function.address >= section.address + section_size)
    {
        // ANOMALY FOUND
        // ..
    }
