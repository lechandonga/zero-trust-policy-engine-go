package loader

import "os"

func statFile(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
