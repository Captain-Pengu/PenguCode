#include "core/logging/crashhandler.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <QStandardPaths>
#include <QTextStream>

#include <csignal>
#include <cstdlib>
#include <exception>
#include <iostream>

#include <QtGlobal>

#ifdef Q_OS_WIN
#include <windows.h>
#include <dbghelp.h>
#endif

namespace pengufoce::core::logging {

namespace {

QMutex &crashLogMutex()
{
    static QMutex mutex;
    return mutex;
}

QString crashLogPath()
{
    QString base = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (base.isEmpty()) {
        base = QDir::tempPath() + QStringLiteral("/PenguFoce");
    }
    QDir dir(base);
    dir.mkpath(QStringLiteral("."));
    return dir.filePath(QStringLiteral("crash.log"));
}

void appendCrashLine(const QString &line)
{
    QMutexLocker locker(&crashLogMutex());
    QFile file(crashLogPath());
    if (file.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream stream(&file);
        stream << line << '\n';
    }
    std::cerr << line.toStdString() << std::endl;
}

void appendCrashBanner(const QString &title)
{
    appendCrashLine(QStringLiteral("============================================================"));
    appendCrashLine(QStringLiteral("[%1] %2")
                        .arg(QDateTime::currentDateTimeUtc().toString(Qt::ISODate), title));
}

#ifdef Q_OS_WIN
void appendWindowsStack()
{
    HANDLE process = GetCurrentProcess();
    SymInitialize(process, nullptr, TRUE);

    void *stack[62];
    const USHORT frames = CaptureStackBackTrace(0, 62, stack, nullptr);
    appendCrashLine(QStringLiteral("Stack frames: %1").arg(frames));

    constexpr DWORD64 symbolBufferSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME;
    char symbolBuffer[symbolBufferSize];
    auto *symbol = reinterpret_cast<SYMBOL_INFO *>(symbolBuffer);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;

    for (USHORT i = 0; i < frames; ++i) {
        const DWORD64 address = reinterpret_cast<DWORD64>(stack[i]);
        DWORD64 displacement = 0;
        QString line = QStringLiteral("#%1 0x%2")
                           .arg(i)
                           .arg(QString::number(address, 16));
        if (SymFromAddr(process, address, &displacement, symbol)) {
            line += QStringLiteral(" %1+0x%2")
                        .arg(QString::fromUtf8(symbol->Name))
                        .arg(QString::number(displacement, 16));
        }
        appendCrashLine(line);
    }
}

LONG WINAPI unhandledExceptionFilter(EXCEPTION_POINTERS *exceptionInfo)
{
    const DWORD code = exceptionInfo && exceptionInfo->ExceptionRecord
        ? exceptionInfo->ExceptionRecord->ExceptionCode
        : 0;
    appendCrashBanner(QStringLiteral("Unhandled exception"));
    appendCrashLine(QStringLiteral("Windows exception code: 0x%1").arg(QString::number(code, 16)));
    appendWindowsStack();
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

void qtMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
    const char *typeName = "DEBUG";
    switch (type) {
    case QtDebugMsg: typeName = "DEBUG"; break;
    case QtInfoMsg: typeName = "INFO"; break;
    case QtWarningMsg: typeName = "WARN"; break;
    case QtCriticalMsg: typeName = "CRIT"; break;
    case QtFatalMsg: typeName = "FATAL"; break;
    }

    appendCrashLine(QStringLiteral("[QT %1] %2 (%3:%4, %5)")
                        .arg(QString::fromLatin1(typeName),
                             message,
                             QString::fromUtf8(context.file ? context.file : ""),
                             QString::number(context.line),
                             QString::fromUtf8(context.function ? context.function : "")));

    if (type == QtFatalMsg) {
        std::abort();
    }
}

void signalHandler(int signalNumber)
{
    appendCrashBanner(QStringLiteral("Fatal signal"));
    appendCrashLine(QStringLiteral("Signal: %1").arg(signalNumber));
#ifdef Q_OS_WIN
    appendWindowsStack();
#endif
    std::_Exit(128 + signalNumber);
}

void terminateHandler()
{
    appendCrashBanner(QStringLiteral("std::terminate"));
    try {
        const auto exception = std::current_exception();
        if (exception) {
            std::rethrow_exception(exception);
        }
    } catch (const std::exception &ex) {
        appendCrashLine(QStringLiteral("Unhandled std::exception: %1").arg(QString::fromUtf8(ex.what())));
    } catch (...) {
        appendCrashLine(QStringLiteral("Unhandled non-standard exception"));
    }
#ifdef Q_OS_WIN
    appendWindowsStack();
#endif
    std::abort();
}

} // namespace

void installCrashHandlers()
{
    qInstallMessageHandler(qtMessageHandler);
    std::set_terminate(terminateHandler);
    std::signal(SIGABRT, signalHandler);
    std::signal(SIGSEGV, signalHandler);
    std::signal(SIGILL, signalHandler);
    std::signal(SIGFPE, signalHandler);
#ifdef Q_OS_WIN
    SetUnhandledExceptionFilter(unhandledExceptionFilter);
#endif
    appendCrashBanner(QStringLiteral("Crash handlers installed"));
}

}
