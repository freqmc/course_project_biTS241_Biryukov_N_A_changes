#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

// Структура для записи значений и порогов
typedef struct {
    int cpu;
    int ram;
    int disk;
} resource_values;

resource_values set_check_values();
int check_threat_level(resource_values current, resource_values limits);
void process_log_file(const wchar_t* filename, resource_values limits);
void extract_values_from_line(const wchar_t* line, resource_values* values);
void analyze_threats(resource_values values, resource_values limits, wchar_t threats[][256], int* threats_count);

int main() {
    setlocale(LC_CTYPE, ""); // Установка локали
    wchar_t filename[256];
    int choice;

    resource_values limits = { 0, 0, 0 }; // Инициализация переменной порогов

    do {
        printf("Выберите необходимую функцию:\n");
        printf("1) Указать пороговые значения\n");
        printf("2) Анализ лог-файла\n");
        printf("Для выхода из программы нажмите на 0\n");
        scanf("%d", &choice);
        switch (choice) {
        case 1:
            limits = set_check_values();
            break;
        case 2:
            printf("Введите имя лог-файла для анализа: ");
            wscanf(L"%ls", filename);
            process_log_file(filename, limits);
            break;
        case 0:
            break;
        default:
            printf("Нет такой функции.\n");
        }
    } while (choice != 0);
    return 0;
}

resource_values set_check_values() {
    resource_values thresholds;
    printf("Введите пороговое значение для загрузки процессора (0-100): ");
    scanf("%d", &thresholds.cpu);
    printf("Введите пороговое значение для загрузки оперативной памяти (0-100): ");
    scanf("%d", &thresholds.ram);
    printf("Введите пороговое значение для загрузки дискового пространства (0-100): ");
    scanf("%d", &thresholds.disk);
    printf("Пороговые значения установлены.\n");
    return thresholds; // Возвращаем пороговые значения
}

int check_threat_level(resource_values current, resource_values limits) {
    int below_threshold = 0;

    if (current.cpu < limits.cpu) {
        below_threshold++;
    }
    if (current.ram < limits.ram) {
        below_threshold++;
    }
    if (current.disk < limits.disk) {
        below_threshold++;
    }

    return below_threshold;
}

void process_log_file(const wchar_t* filename, resource_values limits) {
    FILE* log_file = _wfopen(filename, L"r, ccs=UTF-8");
    if (!log_file) {
        perror("Не удалось открыть файл");
        exit(EXIT_FAILURE);
    }

    resource_values values;
    wchar_t line[256]; // Буфер для строки
    wchar_t threats[100][256]; // Массив строк для угроз
    int threats_count = 0; // Счетчик угроз

    // Считываем строки из файла
    while (fgetws(line, sizeof(line) / sizeof(wchar_t), log_file)) {
        extract_values_from_line(line, &values);
        analyze_threats(values, limits, threats, &threats_count);
    }

    fclose(log_file);

    // Если есть угрозы, предложим пользователю выбрать уровень для сохранения
    if (threats_count > 0) {
        printf("Выберите уровень угроз для сохранения:\n");
        printf("1) ВЫСОКИЙ\n");
        printf("2) СРЕДНИЙ\n");
        printf("3) НИЗКИЙ\n");
        printf("Введите номер уровня (0 для выхода): ");
        int chosen_level;
        scanf("%d", &chosen_level);

        // Запрос на сохранение в файл
        if (chosen_level > 0 && chosen_level <= 3) {
            wchar_t output_filename[256];
            printf("Введите имя файла для сохранения: ");
            wscanf(L"%ls", output_filename);
            FILE* output_file = _wfopen(output_filename, L"w, ccs=UTF-8");
            if (!output_file) {
                perror("Не удалось открыть файл для записи");
                exit(EXIT_FAILURE);
            }

            // Запись угроз в файл
            for (int i = 0; i < threats_count; i++) {
                if ((chosen_level == 1 && wcsstr(threats[i], L"ВЫСОКИЙ")) ||
                    (chosen_level == 2 && wcsstr(threats[i], L"СРЕДНИЙ")) ||
                    (chosen_level == 3 && wcsstr(threats[i], L"НИЗКИЙ"))) {
                    fputws(threats[i], output_file);
                }
            }

            fclose(output_file);
            wprintf(L"Вывод успешно сохранен в файл '%ls'.\n", output_filename);
        }
        else {
            wprintf(L"Выход без сохранения.\n");
        }
    }
    else {
        wprintf(L"Не удалось считать данные из файла. Убедитесь, что формат правильный или данные отсутствуют.\n");
    }
}

void extract_values_from_line(const wchar_t* line, resource_values* values) {
    values->cpu = -1;
    values->ram = -1;
    values->disk = -1;

    wchar_t* cpu_str = wcsstr(line, L"Загрузка процессора");
    wchar_t* ram_str = wcsstr(line, L"Загрузка оперативной памяти");
    wchar_t* disk_str = wcsstr(line, L"Загрузка дискового пространства");

    if (cpu_str) {
        swscanf(cpu_str, L"Загрузка процессора = %d%%", &values->cpu);
    }
    if (ram_str) {
        swscanf(ram_str, L"Загрузка оперативной памяти = %d%%", &values->ram);
    }
    if (disk_str) {
        swscanf(disk_str, L"Загрузка дискового пространства = %d%%", &values->disk);
    }
}

void analyze_threats(resource_values values, resource_values limits, wchar_t threats[][256], int* threats_count) {
    int below_threshold = check_threat_level(values, limits);

    if (below_threshold > 0) {
        wchar_t threat_level[20];
        switch (below_threshold) {
        case 3:
            wcscpy(threat_level, L"ВЫСОКИЙ");
            break;
        case 2:
            wcscpy(threat_level, L"СРЕДНИЙ");
            break;
        case 1:
            wcscpy(threat_level, L"НИЗКИЙ");
            break;
        default:
            return; // Нормальное состояние, пропускаем
        }

        swprintf(threats[*threats_count], 256, L"Уровень угрозы: %ls, Загрузка процессора: %d%%, Загрузка оперативной памяти: %d%%, Загрузка дискового пространства: %d%%\n",
            threat_level, values.cpu, values.ram, values.disk);
        (*threats_count)++;
    }
}