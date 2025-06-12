/**
 * 使用 pdf.js 将 PDF 文件的第一页转换为一个图片 File 对象
 * @param {File} pdfFile - 用户选择的PDF文件
 * @returns {Promise<File>} - 返回一个解析为JPG图片文件的Promise
 */
function convertPdfToImage(pdfFile) {
    return new Promise((resolve, reject) => {
        const fileReader = new FileReader();
        fileReader.onload = function() {
            const typedarray = new Uint8Array(this.result);
            if (typeof pdfjsLib === 'undefined') {
                return reject(new Error("pdf.js 库未加载。"));
            }
            pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://mozilla.github.io/pdf.js/build/pdf.worker.js';
            
            pdfjsLib.getDocument(typedarray).promise.then(pdf => {
                return pdf.getPage(1);
            }).then(page => {
                const scale = 1.5;
                const viewport = page.getViewport({ scale: scale });
                const canvas = document.createElement('canvas');
                const context = canvas.getContext('2d');
                canvas.height = viewport.height;
                canvas.width = viewport.width;

                const renderContext = {
                    canvasContext: context,
                    viewport: viewport
                };
                page.render(renderContext).promise.then(() => {
                    canvas.toBlob(blob => {
                        const newFileName = pdfFile.name.replace(/\.pdf$/i, '.jpg');
                        const imageFile = new File([blob], newFileName, {
                            type: 'image/jpeg',
                            lastModified: Date.now()
                        });
                        resolve(imageFile);
                    }, 'image/jpeg', 0.9);
                });
            }).catch(error => {
                console.error("PDF.js processing error:", error);
                reject(new Error("无法解析此PDF文件，可能已损坏。"));
            });
        };
        fileReader.onerror = (error) => reject(new Error("读取文件出错。"));
        fileReader.readAsArrayBuffer(pdfFile);
    });
}

/**
 * 处理文件输入事件，如果是PDF则进行转换
 * @param {Event} event - 文件选择事件
 * @param {HTMLInputElement} fileInputElement - 文件输入元素
 * @param {HTMLElement} statusElement - 用于显示状态的元素
 */
async function handleFileSelect(event, fileInputElement, statusElement) {
    statusElement.textContent = '';
    const file = event.target.files[0];
    if (!file) return;

    if (file.type === 'application/pdf') {
        statusElement.textContent = '正在处理PDF文件，请稍候...';
        statusElement.style.color = 'hsl(var(--p))';

        try {
            const imageFile = await convertPdfToImage(file);
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(imageFile);
            fileInputElement.files = dataTransfer.files;

            statusElement.textContent = '✅ PDF已成功转换为图片。';
            statusElement.style.color = 'hsl(var(--su))';
        } catch (error) {
            console.error('PDF conversion failed:', error);
            statusElement.textContent = `❌ ${error.message}`;
            statusElement.style.color = 'hsl(var(--er))';
            fileInputElement.value = '';
        }
    }
}