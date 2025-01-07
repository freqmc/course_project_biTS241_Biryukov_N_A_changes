#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

// ��������� ��� ������ �������� � �������
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
    setlocale(LC_CTYPE, ""); // ��������� ������
    wchar_t filename[256];
    int choice;

    resource_values limits = { 0, 0, 0 }; // ������������� ���������� �������

    do {
        printf("�������� ����������� �������:\n");
        printf("1) ������� ��������� ��������\n");
        printf("2) ������ ���-�����\n");
        printf("��� ������ �� ��������� ������� �� 0\n");
        scanf("%d", &choice);
        switch (choice) {
        case 1:
            limits = set_check_values();
            break;
        case 2:
            printf("������� ��� ���-����� ��� �������: ");
            wscanf(L"%ls", filename);
            process_log_file(filename, limits);
            break;
        case 0:
            break;
        default:
            printf("��� ����� �������.\n");
        }
    } while (choice != 0);
    return 0;
}

resource_values set_check_values() {
    resource_values thresholds;
    printf("������� ��������� �������� ��� �������� ���������� (0-100): ");
    scanf("%d", &thresholds.cpu);
    printf("������� ��������� �������� ��� �������� ����������� ������ (0-100): ");
    scanf("%d", &thresholds.ram);
    printf("������� ��������� �������� ��� �������� ��������� ������������ (0-100): ");
    scanf("%d", &thresholds.disk);
    printf("��������� �������� �����������.\n");
    return thresholds; // ���������� ��������� ��������
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
        perror("�� ������� ������� ����");
        exit(EXIT_FAILURE);
    }

    resource_values values;
    wchar_t line[256]; // ����� ��� ������
    wchar_t threats[100][256]; // ������ ����� ��� �����
    int threats_count = 0; // ������� �����

    // ��������� ������ �� �����
    while (fgetws(line, sizeof(line) / sizeof(wchar_t), log_file)) {
        extract_values_from_line(line, &values);
        analyze_threats(values, limits, threats, &threats_count);
    }

    fclose(log_file);

    // ���� ���� ������, ��������� ������������ ������� ������� ��� ����������
    if (threats_count > 0) {
        printf("�������� ������� ����� ��� ����������:\n");
        printf("1) �������\n");
        printf("2) �������\n");
        printf("3) ������\n");
        printf("������� ����� ������ (0 ��� ������): ");
        int chosen_level;
        scanf("%d", &chosen_level);

        // ������ �� ���������� � ����
        if (chosen_level > 0 && chosen_level <= 3) {
            wchar_t output_filename[256];
            printf("������� ��� ����� ��� ����������: ");
            wscanf(L"%ls", output_filename);
            FILE* output_file = _wfopen(output_filename, L"w, ccs=UTF-8");
            if (!output_file) {
                perror("�� ������� ������� ���� ��� ������");
                exit(EXIT_FAILURE);
            }

            // ������ ����� � ����
            for (int i = 0; i < threats_count; i++) {
                if ((chosen_level == 1 && wcsstr(threats[i], L"�������")) ||
                    (chosen_level == 2 && wcsstr(threats[i], L"�������")) ||
                    (chosen_level == 3 && wcsstr(threats[i], L"������"))) {
                    fputws(threats[i], output_file);
                }
            }

            fclose(output_file);
            wprintf(L"����� ������� �������� � ���� '%ls'.\n", output_filename);
        }
        else {
            wprintf(L"����� ��� ����������.\n");
        }
    }
    else {
        wprintf(L"�� ������� ������� ������ �� �����. ���������, ��� ������ ���������� ��� ������ �����������.\n");
    }
}

void extract_values_from_line(const wchar_t* line, resource_values* values) {
    values->cpu = -1;
    values->ram = -1;
    values->disk = -1;

    wchar_t* cpu_str = wcsstr(line, L"�������� ����������");
    wchar_t* ram_str = wcsstr(line, L"�������� ����������� ������");
    wchar_t* disk_str = wcsstr(line, L"�������� ��������� ������������");

    if (cpu_str) {
        swscanf(cpu_str, L"�������� ���������� = %d%%", &values->cpu);
    }
    if (ram_str) {
        swscanf(ram_str, L"�������� ����������� ������ = %d%%", &values->ram);
    }
    if (disk_str) {
        swscanf(disk_str, L"�������� ��������� ������������ = %d%%", &values->disk);
    }
}

void analyze_threats(resource_values values, resource_values limits, wchar_t threats[][256], int* threats_count) {
    int below_threshold = check_threat_level(values, limits);

    if (below_threshold > 0) {
        wchar_t threat_level[20];
        switch (below_threshold) {
        case 3:
            wcscpy(threat_level, L"�������");
            break;
        case 2:
            wcscpy(threat_level, L"�������");
            break;
        case 1:
            wcscpy(threat_level, L"������");
            break;
        default:
            return; // ���������� ���������, ����������
        }

        swprintf(threats[*threats_count], 256, L"������� ������: %ls, �������� ����������: %d%%, �������� ����������� ������: %d%%, �������� ��������� ������������: %d%%\n",
            threat_level, values.cpu, values.ram, values.disk);
        (*threats_count)++;
    }
}