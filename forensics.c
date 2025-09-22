#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
    #include <GL/gl.h>
    #include <GL/glu.h>
#else
    #include <GL/gl.h>
    #include <GL/glu.h>
    #include <GL/glut.h>
    #include <unistd.h>
#endif

// Constants
#define MAX_PATH_LENGTH 1024
#define MAX_FILENAME 256
#define MAX_FILES 1000
#define MAX_HEX_DISPLAY 512
#define WINDOW_WIDTH 1200
#define WINDOW_HEIGHT 800

// Structures
typedef enum {
    FILE_TYPE_FOLDER,
    FILE_TYPE_EXECUTABLE,
    FILE_TYPE_IMAGE,
    FILE_TYPE_DOCUMENT,
    FILE_TYPE_TEXT,
    FILE_TYPE_DELETED,
    FILE_TYPE_UNKNOWN
} FileType;

typedef struct {
    char name[MAX_FILENAME];
    char full_path[MAX_PATH_LENGTH];
    FileType type;
    long size;
    time_t created;
    time_t modified;
    time_t accessed;
    char md5_hash[33];
    char format[32];
    int is_deleted;
    int depth;
    char metadata[512];
    unsigned char hex_data[MAX_HEX_DISPLAY];
    int hex_length;
} FileEntry;

typedef struct {
    char image_path[MAX_PATH_LENGTH];
    char format[32];
    long total_size;
    char compression[32];
    char evidence_number[64];
    time_t creation_date;
    char examiner[128];
} ForensicImage;

// Global variables
FileEntry files[MAX_FILES];
int file_count = 0;
int selected_file_index = 0;
ForensicImage current_image;
int current_tab = 0; // 0=hex, 1=text, 2=metadata, 3=timeline
float camera_angle = 0.0f;
float camera_elevation = 0.0f;
float camera_distance = 10.0f;

// Function prototypes
void init_forensic_data();
void init_opengl();
void display_callback();
void reshape_callback(int width, int height);
void keyboard_callback(unsigned char key, int x, int y);
void special_callback(int key, int x, int y);
void mouse_callback(int button, int state, int x, int y);
void motion_callback(int x, int y);
void timer_callback(int value);
void render_3d_model();
void render_file_tree();
void render_center_panel();
void render_right_panel();
void render_menu_bar();
void render_status_bar();
void update_file_selection(int index);
void generate_hex_data(int file_index);
void calculate_file_hash(int file_index);
void analyze_file_entropy(int file_index);
void draw_text(float x, float y, const char* text, void* font);
void draw_rect(float x, float y, float width, float height, float r, float g, float b);
void draw_3d_cube(float x, float y, float z, float size, float r, float g, float b);
void simulate_file_analysis();

// Initialize forensic data
void init_forensic_data() {
    // Initialize forensic image info
    strcpy(current_image.image_path, "evidence/disk_image.E01");
    strcpy(current_image.format, "E01");
    current_image.total_size = 2500000000; // 2.5 GB
    strcpy(current_image.compression, "ZLIB");
    strcpy(current_image.evidence_number, "EV-2024-001");
    current_image.creation_date = time(NULL);
    strcpy(current_image.examiner, "Digital Forensics Team");

    // Initialize file tree structure
    file_count = 0;
    
    // Root
    strcpy(files[file_count].name, "disk_image.E01");
    strcpy(files[file_count].full_path, "/");
    files[file_count].type = FILE_TYPE_FOLDER;
    files[file_count].size = current_image.total_size;
    files[file_count].depth = 0;
    files[file_count].is_deleted = 0;
    file_count++;

    // Windows folder
    strcpy(files[file_count].name, "Windows");
    strcpy(files[file_count].full_path, "/Windows");
    files[file_count].type = FILE_TYPE_FOLDER;
    files[file_count].size = 15000000;
    files[file_count].depth = 1;
    files[file_count].is_deleted = 0;
    file_count++;

    // System32
    strcpy(files[file_count].name, "System32");
    strcpy(files[file_count].full_path, "/Windows/System32");
    files[file_count].type = FILE_TYPE_FOLDER;
    files[file_count].size = 8000000;
    files[file_count].depth = 2;
    files[file_count].is_deleted = 0;
    file_count++;

    // notepad.exe
    strcpy(files[file_count].name, "notepad.exe");
    strcpy(files[file_count].full_path, "/Windows/System32/notepad.exe");
    files[file_count].type = FILE_TYPE_EXECUTABLE;
    files[file_count].size = 179712;
    files[file_count].depth = 3;
    files[file_count].is_deleted = 0;
    strcpy(files[file_count].format, "PE");
    strcpy(files[file_count].md5_hash, "a1b2c3d4e5f6789012345678901234ab");
    file_count++;

    // calc.exe
    strcpy(files[file_count].name, "calc.exe");
    strcpy(files[file_count].full_path, "/Windows/System32/calc.exe");
    files[file_count].type = FILE_TYPE_EXECUTABLE;
    files[file_count].size = 27648;
    files[file_count].depth = 3;
    files[file_count].is_deleted = 0;
    strcpy(files[file_count].format, "PE");
    strcpy(files[file_count].md5_hash, "b2c3d4e5f67890123456789012345abc");
    file_count++;

    // Users folder
    strcpy(files[file_count].name, "Users");
    strcpy(files[file_count].full_path, "/Users");
    files[file_count].type = FILE_TYPE_FOLDER;
    files[file_count].size = 5000000;
    files[file_count].depth = 1;
    files[file_count].is_deleted = 0;
    file_count++;

    // John user folder
    strcpy(files[file_count].name, "John");
    strcpy(files[file_count].full_path, "/Users/John");
    files[file_count].type = FILE_TYPE_FOLDER;
    files[file_count].size = 3000000;
    files[file_count].depth = 2;
    files[file_count].is_deleted = 0;
    file_count++;

    // Documents
    strcpy(files[file_count].name, "Documents");
    strcpy(files[file_count].full_path, "/Users/John/Documents");
    files[file_count].type = FILE_TYPE_FOLDER;
    files[file_count].size = 2000000;
    files[file_count].depth = 3;
    files[file_count].is_deleted = 0;
    file_count++;

    // report.pdf
    strcpy(files[file_count].name, "report.pdf");
    strcpy(files[file_count].full_path, "/Users/John/Documents/report.pdf");
    files[file_count].type = FILE_TYPE_DOCUMENT;
    files[file_count].size = 867328;
    files[file_count].depth = 4;
    files[file_count].is_deleted = 0;
    strcpy(files[file_count].format, "PDF");
    strcpy(files[file_count].md5_hash, "c3d4e5f678901234567890123456abcd");
    file_count++;

    // photo.jpg
    strcpy(files[file_count].name, "photo.jpg");
    strcpy(files[file_count].full_path, "/Users/John/Documents/photo.jpg");
    files[file_count].type = FILE_TYPE_IMAGE;
    files[file_count].size = 2097152;
    files[file_count].depth = 4;
    files[file_count].is_deleted = 0;
    strcpy(files[file_count].format, "JPEG");
    strcpy(files[file_count].md5_hash, "d4e5f67890123456789012345678abcd");
    file_count++;

    // Program Files
    strcpy(files[file_count].name, "Program Files");
    strcpy(files[file_count].full_path, "/Program Files");
    files[file_count].type = FILE_TYPE_FOLDER;
    files[file_count].size = 1000000000;
    files[file_count].depth = 1;
    files[file_count].is_deleted = 0;
    file_count++;

    // Deleted file
    strcpy(files[file_count].name, "deleted_file.txt (recovered)");
    strcpy(files[file_count].full_path, "/deleted_file.txt");
    files[file_count].type = FILE_TYPE_DELETED;
    files[file_count].size = 4096;
    files[file_count].depth = 1;
    files[file_count].is_deleted = 1;
    strcpy(files[file_count].format, "TXT");
    strcpy(files[file_count].md5_hash, "e5f678901234567890123456789abcde");
    file_count++;

    // Generate initial hex data for selected file
    generate_hex_data(selected_file_index);
}

// Generate hex data for file preview
void generate_hex_data(int file_index) {
    if (file_index < 0 || file_index >= file_count) return;
    
    FileEntry* file = &files[file_index];
    
    // Simulate different hex patterns based on file type
    switch (file->type) {
        case FILE_TYPE_EXECUTABLE:
            // PE header pattern
            file->hex_data[0] = 0x4D; file->hex_data[1] = 0x5A; // MZ
            file->hex_data[2] = 0x90; file->hex_data[3] = 0x00;
            file->hex_data[4] = 0x03; file->hex_data[5] = 0x00;
            for (int i = 6; i < MAX_HEX_DISPLAY; i++) {
                file->hex_data[i] = rand() % 256;
            }
            break;
        case FILE_TYPE_IMAGE:
            // JPEG header pattern
            file->hex_data[0] = 0xFF; file->hex_data[1] = 0xD8; // JPEG SOI
            file->hex_data[2] = 0xFF; file->hex_data[3] = 0xE0; // JFIF marker
            for (int i = 4; i < MAX_HEX_DISPLAY; i++) {
                file->hex_data[i] = rand() % 256;
            }
            break;
        case FILE_TYPE_DOCUMENT:
            // PDF header pattern
            file->hex_data[0] = 0x25; file->hex_data[1] = 0x50; // %P
            file->hex_data[2] = 0x44; file->hex_data[3] = 0x46; // DF
            file->hex_data[4] = 0x2D; file->hex_data[5] = 0x31; // -1
            for (int i = 6; i < MAX_HEX_DISPLAY; i++) {
                file->hex_data[i] = rand() % 256;
            }
            break;
        default:
            // Random data for other types
            for (int i = 0; i < MAX_HEX_DISPLAY; i++) {
                file->hex_data[i] = rand() % 256;
            }
            break;
    }
    
    file->hex_length = MAX_HEX_DISPLAY;
}

// Initialize OpenGL
void init_opengl() {
    glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_LIGHTING);
    glEnable(GL_LIGHT0);
    
    GLfloat light_position[] = {1.0f, 1.0f, 1.0f, 0.0f};
    GLfloat light_ambient[] = {0.2f, 0.2f, 0.2f, 1.0f};
    GLfloat light_diffuse[] = {0.8f, 0.8f, 0.8f, 1.0f};
    
    glLightfv(GL_LIGHT0, GL_POSITION, light_position);
    glLightfv(GL_LIGHT0, GL_AMBIENT, light_ambient);
    glLightfv(GL_LIGHT0, GL_DIFFUSE, light_diffuse);
    
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    gluPerspective(45.0, (double)WINDOW_WIDTH/(double)WINDOW_HEIGHT, 0.1, 100.0);
    glMatrixMode(GL_MODELVIEW);
}

// Display callback
void display_callback() {
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    
    // Set viewport for entire window
    glViewport(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
    
    // Render UI components
    render_menu_bar();
    render_file_tree();
    render_center_panel();
    render_right_panel();
    render_status_bar();
    
    glutSwapBuffers();
}

// Render 3D model in right panel
void render_3d_model() {
    // Set viewport for 3D area (right panel, upper section)
    glViewport(WINDOW_WIDTH * 0.67f, WINDOW_HEIGHT * 0.4f, 
               WINDOW_WIDTH * 0.33f, WINDOW_HEIGHT * 0.35f);
    
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    gluPerspective(45.0, 1.0, 0.1, 100.0);
    
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    
    // Position camera
    gluLookAt(camera_distance * cos(camera_angle * M_PI / 180.0f) * cos(camera_elevation * M_PI / 180.0f),
              camera_distance * sin(camera_elevation * M_PI / 180.0f),
              camera_distance * sin(camera_angle * M_PI / 180.0f) * cos(camera_elevation * M_PI / 180.0f),
              0.0f, 0.0f, 0.0f,
              0.0f, 1.0f, 0.0f);
    
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_LIGHTING);
    
    // Draw 3D representation of file structure
    float x = 0.0f, y = 0.0f, z = 0.0f;
    for (int i = 0; i < file_count && i < 20; i++) { // Limit for performance
        FileEntry* file = &files[i];
        float size_factor = log10((float)file->size + 1) * 0.1f;
        
        // Color based on file type
        float r = 0.5f, g = 0.5f, b = 0.5f;
        switch (file->type) {
            case FILE_TYPE_FOLDER: r = 1.0f; g = 1.0f; b = 0.0f; break;
            case FILE_TYPE_EXECUTABLE: r = 1.0f; g = 0.0f; b = 0.0f; break;
            case FILE_TYPE_IMAGE: r = 0.0f; g = 1.0f; b = 0.0f; break;
            case FILE_TYPE_DOCUMENT: r = 0.0f; g = 0.0f; b = 1.0f; break;
            case FILE_TYPE_DELETED: r = 1.0f; g = 0.0f; b = 1.0f; break;
        }
        
        if (i == selected_file_index) {
            r += 0.3f; g += 0.3f; b += 0.3f;
        }
        
        draw_3d_cube(x, y, z, size_factor, r, g, b);
        
        // Arrange in spiral pattern
        float angle = i * 0.5f;
        float radius = 1.0f + i * 0.2f;
        x = radius * cos(angle);
        z = radius * sin(angle);
        y = file->depth * 0.5f;
    }
    
    glDisable(GL_LIGHTING);
    glDisable(GL_DEPTH_TEST);
}

// Draw 3D cube
void draw_3d_cube(float x, float y, float z, float size, float r, float g, float b) {
    glPushMatrix();
    glTranslatef(x, y, z);
    glScalef(size, size, size);
    
    glColor3f(r, g, b);
    
    // Draw cube faces
    glBegin(GL_QUADS);
    
    // Front face
    glNormal3f(0.0f, 0.0f, 1.0f);
    glVertex3f(-0.5f, -0.5f,  0.5f);
    glVertex3f( 0.5f, -0.5f,  0.5f);
    glVertex3f( 0.5f,  0.5f,  0.5f);
    glVertex3f(-0.5f,  0.5f,  0.5f);
    
    // Back face
    glNormal3f(0.0f, 0.0f, -1.0f);
    glVertex3f(-0.5f, -0.5f, -0.5f);
    glVertex3f(-0.5f,  0.5f, -0.5f);
    glVertex3f( 0.5f,  0.5f, -0.5f);
    glVertex3f( 0.5f, -0.5f, -0.5f);
    
    // Top face
    glNormal3f(0.0f, 1.0f, 0.0f);
    glVertex3f(-0.5f,  0.5f, -0.5f);
    glVertex3f(-0.5f,  0.5f,  0.5f);
    glVertex3f( 0.5f,  0.5f,  0.5f);
    glVertex3f( 0.5f,  0.5f, -0.5f);
    
    // Bottom face
    glNormal3f(0.0f, -1.0f, 0.0f);
    glVertex3f(-0.5f, -0.5f, -0.5f);
    glVertex3f( 0.5f, -0.5f, -0.5f);
    glVertex3f( 0.5f, -0.5f,  0.5f);
    glVertex3f(-0.5f, -0.5f,  0.5f);
    
    // Right face
    glNormal3f(1.0f, 0.0f, 0.0f);
    glVertex3f( 0.5f, -0.5f, -0.5f);
    glVertex3f( 0.5f,  0.5f, -0.5f);
    glVertex3f( 0.5f,  0.5f,  0.5f);
    glVertex3f( 0.5f, -0.5f,  0.5f);
    
    // Left face
    glNormal3f(-1.0f, 0.0f, 0.0f);
    glVertex3f(-0.5f, -0.5f, -0.5f);
    glVertex3f(-0.5f, -0.5f,  0.5f);
    glVertex3f(-0.5f,  0.5f,  0.5f);
    glVertex3f(-0.5f,  0.5f, -0.5f);
    
    glEnd();
    glPopMatrix();
}

// Render file tree (left panel)
void render_file_tree() {
    // Set 2D rendering mode
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(0, WINDOW_WIDTH, 0, WINDOW_HEIGHT, -1, 1);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    
    // Draw left panel background
    draw_rect(0, 100, WINDOW_WIDTH * 0.25f, WINDOW_HEIGHT - 150, 0.15f, 0.15f, 0.15f);
    
    // Draw panel header
    draw_rect(0, WINDOW_HEIGHT - 150, WINDOW_WIDTH * 0.25f, 30, 0.18f, 0.18f, 0.18f);
    glColor3f(0.9f, 0.9f, 0.9f);
    draw_text(10, WINDOW_HEIGHT - 135, "File Structure", GLUT_BITMAP_HELVETICA_12);
    
    // Draw file entries
    float y_pos = WINDOW_HEIGHT - 180;
    for (int i = 0; i < file_count; i++) {
        FileEntry* file = &files[i];
        
        // Highlight selected file
        if (i == selected_file_index) {
            draw_rect(5, y_pos - 15, WINDOW_WIDTH * 0.25f - 10, 20, 0.0f, 0.4f, 0.8f);
        }
        
        // Set color based on file type and status
        if (file->is_deleted) {
            glColor3f(1.0f, 0.4f, 0.4f); // Red for deleted files
        } else {
            glColor3f(0.9f, 0.9f, 0.9f); // White for normal files
        }
        
        // Indent based on depth
        float indent = file->depth * 15.0f;
        
        // Draw file icon and name
        char display_text[300];
        const char* icon;
        switch (file->type) {
            case FILE_TYPE_FOLDER: icon = "📁"; break;
            case FILE_TYPE_EXECUTABLE: icon = "⚙️"; break;
            case FILE_TYPE_IMAGE: icon = "🖼️"; break;
            case FILE_TYPE_DOCUMENT: icon = "📄"; break;
            case FILE_TYPE_DELETED: icon = "🗑️"; break;
            default: icon = "📄"; break;
        }
        
        snprintf(display_text, sizeof(display_text), "%s %s", icon, file->name);
        draw_text(10 + indent, y_pos, display_text, GLUT_BITMAP_HELVETICA_10);
        
        y_pos -= 25;
        if (y_pos < 120) break; // Don't overflow panel
    }
}

// Render center panel (file format info and preview)
void render_center_panel() {
    float panel_x = WINDOW_WIDTH * 0.25f;
    float panel_width = WINDOW_WIDTH * 0.42f;
    
    // Draw center panel background
    draw_rect(panel_x, 100, panel_width, WINDOW_HEIGHT - 150, 0.12f, 0.12f, 0.12f);
    
    FileEntry* selected_file = &files[selected_file_index];
    
    // File format section
    draw_rect(panel_x, WINDOW_HEIGHT - 250, panel_width, 100, 0.15f, 0.15f, 0.15f);
    glColor3f(0.9f, 0.9f, 0.9f);
    draw_text(panel_x + 10, WINDOW_HEIGHT - 165, "File Format Information", GLUT_BITMAP_HELVETICA_12);
    
    // Format details
    char info_text[256];
    glColor3f(0.0f, 0.8f, 1.0f);
    
    snprintf(info_text, sizeof(info_text), "Format: %s", selected_file->format);
    draw_text(panel_x + 20, WINDOW_HEIGHT - 190, info_text, GLUT_BITMAP_HELVETICA_10);
    
    snprintf(info_text, sizeof(info_text), "Size: %ld bytes", selected_file->size);
    draw_text(panel_x + 20, WINDOW_HEIGHT - 205, info_text, GLUT_BITMAP_HELVETICA_10);
    
    snprintf(info_text, sizeof(info_text), "MD5: %s", selected_file->md5_hash);
    draw_text(panel_x + 20, WINDOW_HEIGHT - 220, info_text, GLUT_BITMAP_HELVETICA_10);
    
    snprintf(info_text, sizeof(info_text), "Path: %s", selected_file->full_path);
    draw_text(panel_x + 20, WINDOW_HEIGHT - 235, info_text, GLUT_BITMAP_HELVETICA_10);
    
    // Preview section
    float preview_y = WINDOW_HEIGHT - 260;
    float preview_height = preview_y - 120;
    draw_rect(panel_x, 120, panel_width, preview_height, 0.08f, 0.08f, 0.08f);
    
    glColor3f(0.9f, 0.9f, 0.9f);
    draw_text(panel_x + 10, preview_y - 20, "File Preview", GLUT_BITMAP_HELVETICA_12);
    
    // Tab buttons
    const char* tabs[] = {"Hex", "Text", "Meta", "Timeline"};
    for (int i = 0; i < 4; i++) {
        float tab_x = panel_x + 20 + i * 60;
        float tab_y = preview_y - 50;
        
        if (i == current_tab) {
            draw_rect(tab_x, tab_y, 55, 20, 0.0f, 0.4f, 0.8f);
            glColor3f(1.0f, 1.0f, 1.0f);
        } else {
            draw_rect(tab_x, tab_y, 55, 20, 0.2f, 0.2f, 0.2f);
            glColor3f(0.7f, 0.7f, 0.7f);
        }
        
        draw_text(tab_x + 15, tab_y + 5, tabs[i], GLUT_BITMAP_HELVETICA_10);
    }
    
    // Preview content based on current tab
    glColor3f(0.8f, 0.8f, 0.8f);
    float content_y = preview_y - 80;
    
    switch (current_tab) {
        case 0: // Hex view
            for (int i = 0; i < 8 && i * 16 < selected_file->hex_length; i++) {
                char hex_line[128];
                char ascii_line[20];
                
                snprintf(hex_line, sizeof(hex_line), "%08X: ", i * 16);
                
                for (int j = 0; j < 16 && (i * 16 + j) < selected_file->hex_length; j++) {
                    char byte_hex[4];
                    unsigned char byte = selected_file->hex_data[i * 16 + j];
                    snprintf(byte_hex, sizeof(byte_hex), "%02X ", byte);
                    strcat(hex_line, byte_hex);
                    
                    ascii_line[j] = (byte >= 32 && byte <= 126) ? byte : '.';
                }
                ascii_line[16] = '\0';
                
                strcat(hex_line, " | ");
                strcat(hex_line, ascii_line);
                
                draw_text(panel_x + 20, content_y - i * 15, hex_line, GLUT_BITMAP_8_BY_13);
            }
            break;
            
        case 1: // Text view
            draw_text(panel_x + 20, content_y, "Text representation of file content...", GLUT_BITMAP_HELVETICA_10);
            draw_text(panel_x + 20, content_y - 20, "Binary files may show extracted strings.", GLUT_BITMAP_HELVETICA_10);
            break;
            
        case 2: // Metadata
            snprintf(info_text, sizeof(info_text), "Created: %s", ctime(&selected_file->created));
            draw_text(panel_x + 20, content_y, info_text, GLUT_BITMAP_HELVETICA_10);
            snprintf(info_text, sizeof(info_text), "Modified: %s", ctime(&selected_file->modified));
            draw_text(panel_x + 20, content_y - 20, info_text, GLUT_BITMAP_HELVETICA_10);
            break;
            
        case 3: // Timeline
            draw_text(panel_x + 20, content_y, "📅 File creation event", GLUT_BITMAP_HELVETICA_10);
            draw_text(panel_x + 20, content_y - 20, "✏️ Last modification", GLUT_BITMAP_HELVETICA_10);
            draw_text(panel_x + 20, content_y - 40, "🔍 Forensic analysis started", GLUT_BITMAP_HELVETICA_10);
            break;
    }
}

// Render right panel (3D model and analysis)
void render_right_panel() {
    float panel_x = WINDOW_WIDTH * 0.67f;
    float panel_width = WINDOW_WIDTH * 0.33f;
    
    // Draw right panel background
    draw_rect(panel_x, 100, panel_width, WINDOW_HEIGHT - 150, 0.15f, 0.15f, 0.15f);
    
    // Panel header
    draw_rect(panel_x, WINDOW_HEIGHT - 150, panel_width, 30, 0.18f, 0.18f, 0.18f);
    glColor3f(0.9f, 0.9f, 0.9f);
    draw_text(panel_x + 10, WINDOW_HEIGHT - 135, "Visualization & Analysis", GLUT_BITMAP_HELVETICA_12);
    
    // 3D Model section header
    glColor3f(0.0f, 0.8f, 1.0f);
    draw_text(panel_x + 10, WINDOW_HEIGHT - 165, "3D File Structure Model", GLUT_BITMAP_HELVETICA_10);
    
    // 3D visualization area border
    float viz_y = WINDOW_HEIGHT - 400;
    draw_rect(panel_x + 5, viz_y, panel_width - 10, 220, 0.05f, 0.05f, 0.05f);
    
    // Render 3D model
    render_3d_model();
    
    // Analysis section
    FileEntry* selected_file = &files[selected_file_index];
    
    glColor3f(0.0f, 0.8f, 1.0f);
    draw_text(panel_x + 10, viz_y - 20, "File Analysis", GLUT_BITMAP_HELVETICA_12);
    
    // Analysis details
    char analysis_text[256];
    glColor3f(0.8f, 0.8f, 0.8f);
    
    const char* file_type_str;
    switch (selected_file->type) {
        case FILE_TYPE_EXECUTABLE: file_type_str = "PE Executable"; break;
        case FILE_TYPE_IMAGE: file_type_str = "JPEG Image"; break;
        case FILE_TYPE_DOCUMENT: file_type_str = "PDF Document"; break;
        case FILE_TYPE_FOLDER: file_type_str = "Directory"; break;
        case FILE_TYPE_DELETED: file_type_str = "Recovered File"; break;
        default: file_type_str = "Unknown"; break;
    }
    
    snprintf(analysis_text, sizeof(analysis_text), "File Type: %s", file_type_str);
    draw_text(panel_x + 15, viz_y - 45, analysis_text, GLUT_BITMAP_HELVETICA_10);
    
    snprintf(analysis_text, sizeof(analysis_text), "Architecture: %s", 
             selected_file->type == FILE_TYPE_EXECUTABLE ? "x86-64" : "N/A");
    draw_text(panel_x + 15, viz_y - 65, analysis_text, GLUT_BITMAP_HELVETICA_10);
    
    float entropy = ((float)(selected_file->size % 100)) / 100.0f * 8.0f;
    snprintf(analysis_text, sizeof(analysis_text), "Entropy: %.1f/8.0", entropy);
    draw_text(panel_x + 15, viz_y - 85, analysis_text, GLUT_BITMAP_HELVETICA_10);
    
    snprintf(analysis_text, sizeof(analysis_text), "Packed: %s", 
             entropy > 7.5f ? "Yes" : "No");
    draw_text(panel_x + 15, viz_y - 105, analysis_text, GLUT_BITMAP_HELVETICA_10);
    
    snprintf(analysis_text, sizeof(analysis_text), "Digital Signature: %s",
             selected_file->type == FILE_TYPE_EXECUTABLE ? "Valid" : "N/A");
    draw_text(panel_x + 15, viz_y - 125, analysis_text, GLUT_BITMAP_HELVETICA_10);
    
    // Threat level
    glColor3f(entropy > 7.0f ? 1.0f : 0.0f, entropy < 6.0f ? 1.0f : 0.0f, 0.0f);
    const char* threat_level = entropy > 7.0f ? "High" : (entropy > 5.0f ? "Medium" : "Low");
    snprintf(analysis_text, sizeof(analysis_text), "Threat Level: %s", threat_level);
    draw_text(panel_x + 15, viz_y - 145, analysis_text, GLUT_BITMAP_HELVETICA_10);
    
    glColor3f(0.8f, 0.8f, 0.8f);
    snprintf(analysis_text, sizeof(analysis_text), "File System: NTFS");
    draw_text(panel_x + 15, viz_y - 165, analysis_text, GLUT_BITMAP_HELVETICA_10);
    
    // Controls info
    glColor3f(0.6f, 0.6f, 0.6f);
    draw_text(panel_x + 10, 180, "3D Controls:", GLUT_BITMAP_HELVETICA_10);
    draw_text(panel_x + 10, 165, "Mouse: Rotate view", GLUT_BITMAP_8_BY_13);
    draw_text(panel_x + 10, 150, "Scroll: Zoom in/out", GLUT_BITMAP_8_BY_13);
    draw_text(panel_x + 10, 135, "Arrows: Navigate files", GLUT_BITMAP_8_BY_13);
}

// Render menu bar
void render_menu_bar() {
    // Menu bar background
    draw_rect(0, WINDOW_HEIGHT - 50, WINDOW_WIDTH, 50, 0.18f, 0.18f, 0.18f);
    
    // Application title
    glColor3f(0.0f, 0.8f, 1.0f);
    draw_text(20, WINDOW_HEIGHT - 25, "Charon - Digital Forensics Tool", GLUT_BITMAP_HELVETICA_18);
    
    // Version
    glColor3f(0.6f, 0.6f, 0.6f);
    draw_text(WINDOW_WIDTH - 80, WINDOW_HEIGHT - 25, "v1.0.0", GLUT_BITMAP_HELVETICA_12);
    
    // Menu items
    const char* menu_items[] = {"File", "Edit", "View", "Tools", "Analysis", "Help"};
    glColor3f(0.9f, 0.9f, 0.9f);
    for (int i = 0; i < 6; i++) {
        draw_text(20 + i * 80, WINDOW_HEIGHT - 75, menu_items[i], GLUT_BITMAP_HELVETICA_12);
    }
    
    // Menu separator line
    draw_rect(0, WINDOW_HEIGHT - 100, WINDOW_WIDTH, 2, 0.25f, 0.25f, 0.25f);
}

// Render status bar
void render_status_bar() {
    // Status bar background
    draw_rect(0, 0, WINDOW_WIDTH, 100, 0.18f, 0.18f, 0.18f);
    
    // Status information
    char status_text[512];
    glColor3f(0.8f, 0.8f, 0.8f);
    
    snprintf(status_text, sizeof(status_text), 
             "Processing: %s | Files analyzed: %d | Evidence: %s", 
             current_image.image_path, file_count, current_image.evidence_number);
    draw_text(20, 70, status_text, GLUT_BITMAP_HELVETICA_10);
    
    snprintf(status_text, sizeof(status_text), 
             "Current operation: File signature analysis | Selected: %s", 
             files[selected_file_index].name);
    draw_text(20, 50, status_text, GLUT_BITMAP_HELVETICA_10);
    
    // Progress bar
    float progress_width = WINDOW_WIDTH - 40;
    float progress_height = 10;
    float progress_y = 20;
    
    // Progress bar background
    draw_rect(20, progress_y, progress_width, progress_height, 0.1f, 0.1f, 0.1f);
    
    // Progress bar fill (simulate progress)
    static float progress = 0.45f;
    progress += 0.001f;
    if (progress > 1.0f) progress = 0.0f;
    
    draw_rect(20, progress_y, progress_width * progress, progress_height, 0.0f, 0.8f, 1.0f);
    
    // Progress percentage
    glColor3f(0.9f, 0.9f, 0.9f);
    snprintf(status_text, sizeof(status_text), "%.1f%%", progress * 100);
    draw_text(WINDOW_WIDTH - 80, progress_y + 2, status_text, GLUT_BITMAP_8_BY_13);
}

// Update file selection and related data
void update_file_selection(int index) {
    if (index < 0 || index >= file_count) return;
    
    selected_file_index = index;
    
    // Generate new hex data for selected file
    generate_hex_data(index);
    
    // Update timestamps
    files[index].created = time(NULL) - (rand() % 86400 * 30); // Random time in last 30 days
    files[index].modified = files[index].created + (rand() % 86400); // Modified after creation
    files[index].accessed = time(NULL) - (rand() % 86400); // Recently accessed
    
    // Calculate file hash (simulate)
    calculate_file_hash(index);
    
    // Trigger display update
    glutPostRedisplay();
}

// Calculate file hash (simulated)
void calculate_file_hash(int file_index) {
    if (file_index < 0 || file_index >= file_count) return;
    
    // Simulate MD5 hash calculation based on file name and size
    unsigned int hash = 0;
    FileEntry* file = &files[file_index];
    
    for (int i = 0; file->name[i]; i++) {
        hash = hash * 31 + file->name[i];
    }
    hash ^= file->size;
    
    snprintf(file->md5_hash, sizeof(file->md5_hash), 
             "%08x%08x%08x%08x", hash, hash ^ 0x12345678, 
             hash ^ 0xabcdefab, hash ^ 0x87654321);
}

// Draw text helper function
void draw_text(float x, float y, const char* text, void* font) {
    glRasterPos2f(x, y);
    while (*text) {
        glutBitmapCharacter(font, *text++);
    }
}

// Draw rectangle helper function
void draw_rect(float x, float y, float width, float height, float r, float g, float b) {
    glColor3f(r, g, b);
    glBegin(GL_QUADS);
    glVertex2f(x, y);
    glVertex2f(x + width, y);
    glVertex2f(x + width, y + height);
    glVertex2f(x, y + height);
    glEnd();
}

// Reshape callback
void reshape_callback(int width, int height) {
    glViewport(0, 0, width, height);
    glutPostRedisplay();
}

// Keyboard callback
void keyboard_callback(unsigned char key, int x, int y) {
    switch (key) {
        case 27: // ESC key
            exit(0);
            break;
        case '1':
        case '2':
        case '3':
        case '4':
            current_tab = key - '1';
            glutPostRedisplay();
            break;
        case 'r':
        case 'R':
            // Reset camera
            camera_angle = 0.0f;
            camera_elevation = 0.0f;
            camera_distance = 10.0f;
            glutPostRedisplay();
            break;
        case 'f':
        case 'F':
            // Toggle fullscreen (if supported)
            glutFullScreen();
            break;
    }
}

// Special keys callback (arrow keys, etc.)
void special_callback(int key, int x, int y) {
    switch (key) {
        case GLUT_KEY_UP:
            if (selected_file_index > 0) {
                update_file_selection(selected_file_index - 1);
            }
            break;
        case GLUT_KEY_DOWN:
            if (selected_file_index < file_count - 1) {
                update_file_selection(selected_file_index + 1);
            }
            break;
        case GLUT_KEY_LEFT:
            camera_angle -= 5.0f;
            glutPostRedisplay();
            break;
        case GLUT_KEY_RIGHT:
            camera_angle += 5.0f;
            glutPostRedisplay();
            break;
        case GLUT_KEY_PAGE_UP:
            camera_elevation += 5.0f;
            if (camera_elevation > 89.0f) camera_elevation = 89.0f;
            glutPostRedisplay();
            break;
        case GLUT_KEY_PAGE_DOWN:
            camera_elevation -= 5.0f;
            if (camera_elevation < -89.0f) camera_elevation = -89.0f;
            glutPostRedisplay();
            break;
    }
}

// Mouse callback
void mouse_callback(int button, int state, int x, int y) {
    static int last_x, last_y;
    
    if (button == GLUT_LEFT_BUTTON && state == GLUT_DOWN) {
        last_x = x;
        last_y = y;
        
        // Check if click is in file tree area
        float normalized_x = (float)x / WINDOW_WIDTH;
        float normalized_y = 1.0f - (float)y / WINDOW_HEIGHT;
        
        if (normalized_x < 0.25f && normalized_y > 0.2f && normalized_y < 0.88f) {
            // Calculate which file was clicked
            int file_index = (0.88f - normalized_y) * file_count / 0.68f;
            if (file_index >= 0 && file_index < file_count) {
                update_file_selection(file_index);
            }
        }
        
        // Check if click is in tab area
        if (normalized_x > 0.25f && normalized_x < 0.67f && 
            normalized_y > 0.55f && normalized_y < 0.6f) {
            int tab_index = (normalized_x - 0.28f) * 4 / 0.25f;
            if (tab_index >= 0 && tab_index < 4) {
                current_tab = tab_index;
                glutPostRedisplay();
            }
        }
    }
    
    // Mouse wheel for zooming 3D view
    if (button == 3) { // Wheel up
        camera_distance -= 1.0f;
        if (camera_distance < 2.0f) camera_distance = 2.0f;
        glutPostRedisplay();
    } else if (button == 4) { // Wheel down
        camera_distance += 1.0f;
        if (camera_distance > 50.0f) camera_distance = 50.0f;
        glutPostRedisplay();
    }
}

// Mouse motion callback
void motion_callback(int x, int y) {
    static int last_x = 0, last_y = 0;
    
    if (last_x != 0 && last_y != 0) {
        float dx = x - last_x;
        float dy = y - last_y;
        
        // Only rotate if mouse is in 3D area
        float normalized_x = (float)x / WINDOW_WIDTH;
        if (normalized_x > 0.67f) {
            camera_angle += dx * 0.5f;
            camera_elevation += dy * 0.5f;
            
            if (camera_elevation > 89.0f) camera_elevation = 89.0f;
            if (camera_elevation < -89.0f) camera_elevation = -89.0f;
            
            glutPostRedisplay();
        }
    }
    
    last_x = x;
    last_y = y;
}

// Timer callback for animations
void timer_callback(int value) {
    // Update any animations here
    camera_angle += 0.2f; // Slow auto-rotation of 3D view
    if (camera_angle >= 360.0f) camera_angle = 0.0f;
    
    glutPostRedisplay();
    glutTimerFunc(50, timer_callback, 0); // 20 FPS
}

// Main function
int main(int argc, char** argv) {
    // Initialize GLUT
    glutInit(&argc, argv);
    glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB | GLUT_DEPTH);
    glutInitWindowSize(WINDOW_WIDTH, WINDOW_HEIGHT);
    glutCreateWindow("Charon - Digital Forensics Tool");
    
    // Initialize application data
    srand(time(NULL));
    init_forensic_data();
    init_opengl();
    
    // Set callback functions
    glutDisplayFunc(display_callback);
    glutReshapeFunc(reshape_callback);
    glutKeyboardFunc(keyboard_callback);
    glutSpecialFunc(special_callback);
    glutMouseFunc(mouse_callback);
    glutMotionFunc(motion_callback);
    glutTimerFunc(50, timer_callback, 0);
    
    // Print usage instructions
    printf("=== Charon Digital Forensics Tool ===\n");
    printf("Controls:\n");
    printf("- Arrow Keys: Navigate file selection / Rotate 3D view\n");
    printf("- Page Up/Down: Adjust 3D view elevation\n");
    printf("- Mouse: Click files to select, drag in 3D area to rotate\n");
    printf("- Mouse Wheel: Zoom 3D view in/out\n");
    printf("- Keys 1-4: Switch preview tabs (Hex/Text/Meta/Timeline)\n");
    printf("- R: Reset 3D camera position\n");
    printf("- F: Toggle fullscreen\n");
    printf("- ESC: Exit application\n");
    printf("\nStarting forensic analysis...\n");
    
    // Start the main loop
    glutMainLoop();
    
    return 0;
}