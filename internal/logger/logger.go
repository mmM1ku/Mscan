package logger

import "github.com/gookit/slog"

const myTemplate = "[{{datetime}}] [{{level}}] {{message}}\n"

var Logger = logger()

func logger() *slog.SugaredLogger {
	l := slog.NewStdLogger()
	l.Configure(func(sl *slog.SugaredLogger) {
		f := sl.Formatter.(*slog.TextFormatter)
		f.EnableColor = true
		f.SetTemplate(myTemplate)
	})
	return l
}
