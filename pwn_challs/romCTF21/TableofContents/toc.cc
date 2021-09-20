#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

#include <string.h>
#include <stdio.h>

void flush();

class LibraryItem {
    public:
        virtual void add_page() = 0;
        virtual void tear_page() = 0;
        virtual void read() = 0;
        virtual ~LibraryItem() {};
        std::string title;
        std::vector<char *> pages;
    private:
        __attribute__((used))
        void win(const char* arg) {
            system(arg);
        }
};

class Book: public LibraryItem {
    public:
        Book(std::string title) {
            this->title = std::move(title);
        }
        virtual void add_page() {
            printf("Enter size of page: ");
            unsigned int size;
            std::cin >> size;
            flush();
            char *buf = (char *)malloc(size);
            printf("Enter data: ");
            std::cin.read(buf, size);
            this->pages.push_back(buf);
        }
        virtual void tear_page() {
            printf("Enter index of page: ");
            unsigned int index;
            std::cin >> index;
            puts(this->pages[index]);
            free(this->pages[index]);
        }
        virtual void read() {
            for (char * &page: this->pages) {
                puts(page);
            }
        }

        virtual void feedback(const char* content) {
            puts("Your feedback is highly valued!");
            memset((void *)content, 0, strlen(content));
        }
};

std::vector<Book *> items;
bool has_borrowed = false;
Book* borrowed = new Book("");

void flush() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }
}

char menu() {
    printf("1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback\n> ");
    char ret;
    scanf(" %c", &ret);
    flush();
    return ret;
}

void add() {
    std::string contents;
    printf("Enter title > ");
    getline(std::cin, contents);
    items.push_back(new Book(contents));
}

void list() {
    for (int i = 0; i < items.size(); i++) {
        std::cout << items[i]->title << std::endl;
    }
};

void fetch() {
    unsigned int index;
    printf("What index to get? ");
    std::cin >> index;
    if (index >= items.size()) {
        puts("That item does not exist");
        return;
    }
    printf("1) Borrow book\n2) Add a page\n3) Tear out page\n> ");
    char choice;
    scanf(" %c", &choice);
    flush();
    std::string contents;
    switch (choice) {
    case '1':
        if (has_borrowed ) {
            puts("You can only have one book borrowed");
            break;
        }
        memcpy((void *)borrowed, (void *)items[index], sizeof(Book));
        free((void *)items[index]);
        printf("Your reference number is: %p\n", items[index]);
        has_borrowed = true;
        break;
    case '2':
        items[index]->add_page();
        break;
    case '3':
        items[index]->tear_page();
        break;
    default:
        puts("Unknown option");
    }

};

void return_book() {
    Book *book;
    printf("Enter reference number: ");
    scanf("%p", &book);
    flush();
    if ((unsigned long)book >= 0x0000700000000000UL) {
        puts("Unauthorized access detected");
        exit(-1);
    }
    memcpy((void *)book, (void *)borrowed, sizeof(Book));
    has_borrowed = false;
    puts("Thank you for returning the book");
}

void leave_feedback() {
    unsigned int index;
    printf("Enter index of book for feedback: ");
    std::cin >> index;
    flush();
    std::string* feedback = new std::string();
    printf("Enter feedback: ");
    getline(std::cin, *feedback);
    items[index]->feedback(feedback->c_str());
}

int main() {
    puts("WELCOME!");
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        char option = menu();
        switch (option) {
        case '1':
            add();
            break;
        case '2':
            list();
            break;
        case '3':
            fetch();
            break;
        case '4':
            return_book();
            break;
        case '5':
            leave_feedback();
            break;
        default:
            puts("Unknown option");
        }
    }
}
