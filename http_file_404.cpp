#include <string>
#include <vector>

#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_file.h"
#include "http_file_404.h"

http_file_404::http_file_404() : http_file_file("/404.html", "text/html", WEB_DIR "/404.html")
{
}

http_file_404::~http_file_404()
{
}
